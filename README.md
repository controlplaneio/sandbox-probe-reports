# sandbox-probe-reports

The **comparison and reporting harness** built on top of
[`sandbox-probe`](https://github.com/controlplaneio/sandbox-probe).

`sandbox-probe` is a single static Go binary you drop *inside* a sandbox to
report what it can see and reach. It is self-contained and useful on its own.
This repository is the other half: everything that turns many probe reports
into a comparison — the scan matrix, the seeder, the per-runtime launchers,
the agent stubs, the baseline-normalised methodology, and the reporting site.

## Why this is a separate repo

Comparing sandboxes is a different piece of software with a much harder
problem — *what counts as a fair comparison?* — and it was generating churn
inside the probe's repo without touching the probe's own behaviour.
Splitting it means the probe stays stable and small, and the comparison
methodology can evolve (including being wrong and getting corrected) without
that ever destabilising the thing people depend on.

That "being wrong and getting corrected" is not hypothetical. The split was
triggered by discovering that the existing comparison rows for five sandbox
runtimes were not measuring what they claimed to — see
[Methodology](#methodology).

## Dependency on the probe

This repo carries its own `go.mod` requiring a pinned
`github.com/controlplaneio/sandbox-probe`, rather than checking the probe out
at a ref. Dependabot's `gomod` ecosystem tracks a `go.mod` requirement
automatically and resolves off git tags directly; a `ref:` pinned inside a
workflow is an opaque string nothing watches, and would rot silently.

The requirement is declared with Go's **`tool` directive**, not a bare
`require`:

```
tool github.com/controlplaneio/sandbox-probe
```

That matters. This repo imports no probe package — it *runs the binary*. A
bare `require` is therefore unused, and `go mod tidy` deletes it, taking the
Dependabot coverage with it and leaving no trace. The `tool` directive is the
mechanism the toolchain provides for exactly this case, and the smoke job
asserts the pin survives a tidy so it cannot rot back.

Build the pinned probe with:

```sh
go build -o bin/sandbox-probe github.com/controlplaneio/sandbox-probe/v6
```

### Why the pin carries a `/v6`

The probe's module path is `github.com/controlplaneio/sandbox-probe/v6`, and it
has to be. A Go module whose major version is 2 or above must carry the suffix,
or the proxy refuses it outright with *"module path must match major version"*.

That was broken for a long time. The path had no suffix while the tags had
climbed to `v5.2.1`, so every tag from `v4.8.2` onward was unresolvable and
`go get` returned `v1.1.0` from May 2026 — a build predating `list-targets`,
`seed` and `cleanup`, which is to say predating everything this repository
needs. It was fixed in
[controlplaneio/sandbox-probe#52](https://github.com/controlplaneio/sandbox-probe/pull/52)
and first released as `v6.2.1`.

If the probe ever takes a `v7`, the path and the tag move together. They cannot
move apart: `semver.yaml` in that repository carries a `force.major` floor for
exactly this reason.

Dependabot keeps the version current from here.

## The smoke job

`.github/workflows/smoke.yml` runs on **every push and pull request**,
including from forks. It needs no agent CLI, no API key, no model access and
no sandbox runtime — the opposite of the full matrix:

```
assert the probe pin survives `go mod tidy`
go build the probe            # version resolved from go.mod — the Dependabot pin
run the seeder against it     # reads list-targets across the repo boundary
run one direct baseline scan
assert the report parses and carries an expected finding type
```

One job, three failure modes it exists to catch:

- **The pin is dropped or broken** — tidy assertion, or the build step.
- **The binary is unusable** — a scan producing no parseable report fails
  here rather than in the next weekly matrix run.
- **The registry contract drifts** — the seeder reads `list-targets` from a
  now-external module. A schema change in the probe that the seeder cannot
  parse fails here. This is the drift the split makes possible and nothing
  else catches.

## What lands here

Per the repo-split decision (recorded in the wayfinder maps under
[`.scratch/`](.scratch/) in this repository — `seed-ipc-targets` and
`sandbox-canary-nesting` moved wholesale, `profile-attestation` from its
ticket 05 onward):

- ✅ `go.mod` — the pinned probe dependency
- ✅ `scripts/seed-decoys.sh` — parent-side canary seeding
- ✅ `.github/workflows/smoke.yml` — the boundary smoke job
- ✅ `.github/workflows/scan-matrix.yaml` — the per-harness × OS scan matrix
- ✅ `.github/workflows/scan-gemini.yaml` — the standalone Gemini sandbox-image scan
- ✅ `scripts/run-probe-in-sandbox.sh` + the per-agent stub runners, the shared
  `stub-common.sh` plumbing, `mock-agent-api.mjs`, and the agent run scripts
- ✅ `tests/agent-driven/*.sh` — the baseline/sandbox pair scripts
- ✅ `reports/*.json`, `trajectories/*.json` — the stored fixtures
- ✅ `site/` — the client-side reporting page, and the matrix's aggregate/publish job
- ✅ `docs/mount-cell-moves.md` — the record of which harnesses' Host mounts cell
  moves under the corrected mount enumerator, and `scripts/mount-cell-moves.mjs`
  which produces it from two matrix runs
- ✅ `docs/reporting-site-plan.md`, `docs/adr/0001-*` (the comparison-methodology
  ADR) and [`CONTEXT.md`](CONTEXT.md) — this repository is now the only place
  the comparison-side ubiquitous language is defined. ADR 0002 decides the
  probe's own registry shape and stays with the probe; see
  [its copy there](https://github.com/controlplaneio/sandbox-probe/blob/main/docs/adr/0002-seed-ipc-and-process-targets.md).

**Staying** in `sandbox-probe`: the Go binary (`cmd/`, `pkg/`, `main.go`), its
tests, and `list-targets` — the probe's own registry of what it checks, which
belongs next to the code it describes so the seeder cannot drift from it.
Also staying: `tests/fingerprint/*.sh` and the minimal `run-bwrap.sh` /
`run-docker.sh` / `run-podman.sh` launchers they invoke. Those assert that the
probe's own `sandbox_detection` identifies a runtime — a probe capability, not
a comparison. That is the line between `tests/fingerprint` and the
`tests/agent-driven` scripts that came here.

## Running the matrix

`scan-matrix.yaml` keeps its weekly cron, its `workflow_dispatch`, and its
`matrix/**` push trigger. Its `build` job compiles the probe **from the module
version pinned in `go.mod`** — `go build github.com/controlplaneio/sandbox-probe`
— once per platform, with darwin built on macOS and windows on Windows, and
shares the binaries to the scan jobs as artifacts. Nothing but that binary
comes from outside this repository: every script, stub and config the scan rows
invoke resolves under `scripts/` here.

**History does not migrate.** Files arrive as a fresh commit; the decision
record lives in the ADRs and wayfinder maps rather than in `git log`.

A final `aggregate` job (`needs: [build, scan]`, `if: always()`, so a partially
failed matrix still publishes what succeeded) collects every scan row's report
artifact, appends one commit to the orphan `gh-pages-data` branch at
`data/<run-timestamp>/<os>-<harness>.json`, rebuilds the concatenated
`all-reports.json` from the whole branch history (`scripts/build-site-data.mjs`),
and deploys `site/` + that payload to GitHub Pages
(`scripts/publish-site.sh`). See [ADR 0001](docs/adr/0001-client-side-site-over-data-branch.md).

### Running the attestation

`scan-matrix.yaml` also carries an `attest` job — the declared-versus-actual run
(`scripts/attest-profile.sh`). It seeds the host, takes an unconfined baseline,
resolves a nono registry profile, runs the probe under it with `nono run
--profile <id> --` and nothing else, and publishes the attestation. The profile
is a `workflow_dispatch` input, so dispatching against a different registry
profile attests that one with no code change.

It is in the gated workflow rather than the per-push smoke suite for one reason:

> **Installing a nono registry pack mutates local agent configuration.** It
> splices Codex plugin wiring into `~/.codex/config.toml` and `~/.codex/plugins/`
> at *install* time. `nono`'s `--dry-run` skips sandbox verification and
> execution — **not** pack installation. Confirmed against nono 0.68.0.

So removal is an explicit, verified step, never an assumption
(`scripts/nono-pack.sh`): the mutated paths are snapshotted before the install,
`nono remove` runs from an `EXIT` trap armed *before* the install so a crash
still reverses the splice, and the snapshot is compared afterwards — a run that
leaves residue fails and names the file. Installing removes first rather than
trusting either the pack's idempotence or the last run's cleanup.

To run it on your own machine, understand that the box above applies to *your*
`~/.codex`. The script says so before it installs anything and will not start
until you accept it:

```sh
NONO_PACK_ACK=1 PROFILE=nolabs-ai/codex PROBE=./bin/sandbox-probe ./scripts/attest-profile.sh
```

The same lifecycle backs the `codex-nono` matrix row (`CODEX_NONO_PROFILE` in
`scripts/run-probe-via-codex-stub.sh`). `tests/nono-pack-wiring.test.mjs` runs on
every push and fails if the warning, snapshot or trap ever stops preceding the
install; the real-registry half — that `nono remove` reverses a real pack — is
exercised by the gated job, which deliberately crashes a run mid-way and asserts
the machine came back.

## One-time setup

Both items are now done on `controlplaneio/sandbox-probe-reports`. They are
recorded because neither is visible in the source tree, and because missing
the second one is why this site did not publish for three weeks.

1. **The orphan `gh-pages-data` branch.** `publish-site.sh` creates it on first
   run (`git worktree add --orphan`) if the remote lacks it. The aggregate job
   grants itself `contents: write` to push it. Branch protection is scoped to
   `main` only, so nothing blocks that push — and it must stay that way: the
   job pushes as `github-actions[bot]`, whose commits are not signed, so any
   rule requiring signatures on `~ALL_BRANCHES` would break it silently.
2. **GitHub Pages with the "GitHub Actions" source.** Enabled via
   `gh api -X POST repos/controlplaneio/sandbox-probe-reports/pages -f build_type=workflow`.
   Without it, `actions/configure-pages` fails with *"Get Pages site failed"*
   and every scheduled run dies after successfully writing its data.

`actions/configure-pages` is deliberately left at `enablement: false`. Setting
it true would require this repository's first ever secret — a token with
`administration:write` — to do a job one API call already did.

Nothing here can be verified by running tests; a real matrix run is the
verification.

## What was here before

This repository previously held a single `gemini/sandbox_container/` directory
of 14 daily reports from March 2026, under a CC0 licence. That was a stale
sample in a schema the current site cannot read, and it predates the
baseline-normalised methodology entirely, so its numbers are not comparable
with anything produced now. It did not migrate.

It is not lost: the tag **`pre-migration`** points at the commit before the
fresh start, so those reports and their authorship stay reachable.

The licence changed with it, from CC0-1.0 to Apache-2.0, matching
`controlplaneio/sandbox-probe`.

## Methodology

Full definitions live in [`CONTEXT.md`](CONTEXT.md) — the ubiquitous
language for this repository, and the only place the comparison-side terms
below are defined. What follows is the shape of the methodology; read
`CONTEXT.md` for the precise rules.

**Baseline normalisation.** A finding's *absence* only means "the sandbox
blocked it" if the capability was achievable on that host at all. Everything
is read against an unconfined same-OS **baseline** run — the probe run on the
bare host, before any sandbox is applied.

**Cell states.** Every capability cell in the matrix is one of three
baseline-normalised states:

| State | Meaning |
| --- | --- |
| 🟥 leaked | baseline could do this, this harness still can — a door the sandbox left open |
| 🟩 blocked | baseline could do this, this harness cannot — the sandbox closed a real door |
| ⬜ n/a | baseline could not do this either — nothing was achievable, so nothing was proven |

**Capability categories.** Findings roll up into 8 columns. Seven are
baseline-normalised (a door the baseline had to have for the cell to mean
anything); the eighth, Privileged execution, is absolute (running as root is
🟥 regardless of baseline):

Filesystem read, Filesystem write, Network egress, Local services, IPC
sockets, Process visibility, Host mounts, Privileged execution. An unmapped
future finding type gets an **Other** column rather than being dropped.
Context findings (`sandbox_detection`, `hostname_detection`,
`environment_detection`, `proxy_detection`, `env_secret_detection`) are shown
but not counted.

**Exposure.** The headline scalar: the count of leaked (🟥) capability
categories for one harness identity at one point — 0 to 8. Rising exposure
over time means a widening sandbox; falling means a tightening one.

**Seeding parity.** A finding's absence only proves a block if the target was
*achievable* in the first place — on a bare CI runner most sensitive paths,
sockets, and processes simply don't exist yet. The probe exports its own
target registry (`list-targets`); a seeder soft-plants a decoy at each target
(write only where nothing real already exists) **identically before the
baseline run and every sandbox run, on every runner OS**. Parity is
load-bearing: seed one side and not the other and a real block becomes
indistinguishable from "the decoy was never there" — a false 🟩.
`scripts/seed-decoys.sh` is that one invocation point, in both directions:
no flag plants, `--cleanup` removes. It plants the `file` kind itself and
delegates socket, process and Windows named-pipe decoys to the probe's own
`seed`/`cleanup` (bash cannot `bind()` a socket or serve a pipe), so a new
kind in the registry needs no change on this side. Cleanup runs after every
scan **even when the scan failed**, because a process decoy and a pipe server
are live artifacts a reused runner would otherwise accumulate.

**Time-series identity.** Runs group into one trend line by the tuple
`(os, harness)` (e.g. `macos-claude-sandbox`) — read from tags so a new
harness joins with no code change. A plotted point is a distinct
configuration **fingerprint** (`harness version + probe commit + kernel
release + OS release`); runs sharing a fingerprint collapse to one point, the
axis orders by first-seen, so it's a sequence of distinct configurations, not
wall-clock time.

**Flips.** A **flip** is one capability changing state between two
consecutive points on one identity's time series — 🟩→🟥 is a degradation,
🟥→🟩 is an improvement — attributed to whichever fingerprint component
moved (harness version, probe version, kernel, OS). The **flip-log** is the
chronological list of flips, the actionable text beside the exposure chart.

**Canary nesting.** Canaries are seeded in the *parent* host, and the sandbox
is launched as a genuine child of that seeded parent. The question is whether
a process inside the sandbox can reach out to something outside it. Canaries
are never planted *inside* the sandbox: that would test whether the sandbox's
own environment happens to contain artefacts, which is not the threat model —
a real attacker in a real sandbox is trying to reach *out*.

This is also why the five rootfs-swapping runtimes (docker, podman, bwrap,
nspawn, gvisor, driven directly with no agent) were **retired from the
comparison** rather than fixed. Each was launched as a fresh, disconnected
environment that had never been nested in the seeded parent, so "the sandbox
blocked it" was indistinguishable from "there was never a route there to
begin with". Any sharing flags the harness adds to reconnect them are the
harness's own choice, not a vendor's — so the result would measure our
configuration rather than the sandbox's. Comparisons are only kept where
*someone else* made the configuration decision: an agent vendor shipping its
own sandbox, or a declared, versioned policy profile — see the
[`profile-attestation`](.scratch/profile-attestation/map.md) wayfinder map
for the emerging declared-vs-actual variant of this idea.

That criterion, what it admits and excludes, and how to decide whether a new
row qualifies are recorded in
[ADR 0003](docs/adr/0003-canary-nesting-and-the-comparability-criterion.md).
The per-runtime evidence behind it — each retired runtime's real default
sharing behaviour, the firejail/nono/srt flag audit and the four agent-harness
verifications, with what was actually tested and on what — is
[`docs/nesting-evidence.md`](docs/nesting-evidence.md).

**Vendor defaults on the rows that stay.** srt, firejail and nono are
launched with no restriction this repository invented. firejail gets only
`--quiet` and applies its own default profile; nono keeps only the
working-directory and output-directory grants — it denies everything with
zero flags and will not start without them; srt keeps its deny-by-default
settings file, widened only for writes to the workspace and temp so the probe
can emit a report. **None of the three blocks network egress**, because none
of them does out of the box: those rows now show egress reachable wherever
the same-OS baseline could reach it, and their exposure rises accordingly.
That is the vendor's real posture, not a regression. Dropping firejail's
added syscall filter is also expected to change the kernel mechanisms
reported beside its `firejail` badge — a finding about firejail's own default
profile, recorded in `.github/workflows/scan-matrix.yaml`, not an assertion
to quietly patch.

These three rows stay while a bare container run does not. Each restricts the
seeded parent's own filesystem by policy instead of swapping in a fresh root,
so the run really is a child of the seeded host — and the minimum
hand-authored inline policy needed to start the tool and get a report out is
itself a real deployment pattern: this is how these tools are driven in
practice. That is not circular in the way a bare container run is, where
every route into the sandbox exists only because this repository chose to
open it.

**Attestation (declared vs actual).** A separate comparison, kept out of the
0–8 exposure scale: a declared profile's resolved grants diffed against what
the probe observed under it, every grant landing in one drift class (match,
overclaim, gap, unprovable, unattested) alongside the **coverage** that says how
much of the declared surface was attestable at all. Which declared grant is
observed by which finding, which categories nothing observes and are named
unattested, which are excluded by design, and where nono's own published schema
is stale, are in
[`docs/attestation-mapping.md`](docs/attestation-mapping.md) — read it before
extending either side. It is published as its own page (`site/attestation.html`)
rather than a matrix column, rendering `site/attestation.json`, so a verdict can
be read without nono and without running a scan. That document is either the
checked-in fixture build (`node scripts/build-attestation.mjs`) or an observed
run's, and its own `source` field says which — the two can never be confused.
Producing the observed one is [Running the attestation](#running-the-attestation)
above.

**The `codex-nono` row.** Separately from the attestation, the real Codex CLI
also runs under that same declared profile as an *ordinary* matrix row, beside
the native-sandbox `codex-sandbox` row, on the baseline-normalized methodology
entirely unchanged — two genuine sandboxing choices, read against each other. Its
confinement is `nono run --profile <id> --` and nothing else, so the row measures
the vendor's published claim rather than any flag of ours; everything the run
needs to read or write lives inside a path the profile already grants. It carries
its own harness identity and tags the resolved profile version, so it forms its
own time series and a flip is attributable to a specific published claim.

### Adding a sandbox row

Two things a new runtime needs before it can join the matrix.

**Somebody else must have made the configuration decision** — an agent vendor
shipping its own sandbox, or a declared, versioned policy profile. A raw
runtime whose every sharing decision comes from `run-probe-in-sandbox.sh` is
measuring this repository, not the vendor, and no choice of flags fixes that.

**Every flag you pass must carry a declared reason.** Add the runtime and its
flags to the declaration in
[`tests/vendor-default-flags.test.mjs`](tests/vendor-default-flags.test.mjs),
one reason per flag, from exactly three:

| Reason | Means |
| --- | --- |
| `vendor-default` | reproduces what the tool does with no flags at all; it is written out only because the invocation shape demands it explicitly |
| `minimum-to-run` | without it the tool will not start, or the probe cannot run and emit its report — nono's filesystem grants and srt's settings file are this |
| `output-only` | affects logging or verbosity and never the security boundary — `--quiet`, `--silent` |

Anything needing a fourth reason is a narrowing this project invented, and the
row would measure our configuration rather than the vendor's posture. The guard
runs on every push, reads the launcher as its source of truth, and fails naming
the runtime and the flag — so a flag added, changed or removed there without
updating the declaration fails too. This exact class of bug was found by hand
five separate times before the guard existed.

## What runs the comparison

Everything here compares reports produced by
[`sandbox-probe`](https://github.com/controlplaneio/sandbox-probe) — a
single static Go binary that runs inside a sandbox and records what the
kernel let it do. This repository has no probe of its own; it depends on a
pinned release of it (see [Dependency on the probe](#dependency-on-the-probe)
above). If you want to run the probe standalone, without any of this
methodology, see the probe's own README.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) — the same licence as `sandbox-probe`.
