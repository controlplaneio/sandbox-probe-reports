# Canary-nesting evidence

The evidence base behind
[ADR 0003](adr/0003-canary-nesting-and-the-comparability-criterion.md): what
each sandbox runtime and harness actually shares by default, what non-invasive
plumbing would have looked like, and what was actually run to find out.

The canary test is the one described in the ADR: seed the **parent** host,
launch the sandbox as a genuine **child** of that seeded parent, and ask
whether the process inside can reach what exists outside. Nothing is ever
seeded inside a sandbox.

Every verdict below is reproduced here in full. The original long-form
write-ups (`docs/research/*.md` on the probe repository's `research/*`
branches, cited per entry for provenance) carry the raw command transcripts
only — **no verdict in this index or in ADR 0003 depends on reading one.**
Each entry links to its research ticket in the
[`sandbox-canary-nesting` wayfinder map](../.scratch/sandbox-canary-nesting/map.md),
which carries the question that was asked.

Each entry says the same three things:

- **Default sharing** — what the tool shares with no flags at all.
- **Non-invasive plumbing** — how the probe binary gets in and the report gets
  out without that plumbing itself widening the boundary.
- **Tested** — what was actually run, on what, and what was *not* reached.

---

## The five retired runtimes

These five are retired from the comparison matrix. The evidence is not wasted:
it is what makes the exclusion a finding rather than an assertion. In every
case the runtime *could* have been nested — the reason for retirement is that
the flags doing the nesting would have been this project's own choice. See
ADR 0003's criterion.

### Docker

[Research ticket](../.scratch/sandbox-canary-nesting/issues/01-docker-default-nesting.md)
· write-up `docs/research/docker-default-nesting.md`, branch
`research/docker-default-nesting` (`525caf5`)

- **Default sharing** — filesystem: **nothing**. Every entry in `/proc/mounts`
  inside a zero-flag container is the image's own overlay root or a kernel
  pseudo-filesystem; no bind mount of any kind. A decoy outside the container
  is unreachable by construction. Network: **bridged, not none** — a bare
  container gets a real `eth0`, a default route, working DNS and real outbound
  connectivity (`curl https://1.1.1.1` → HTTP 301). The launcher's
  `--network=none` is therefore *stricter* than Docker's real default, and the
  `-v "$PWD:/work"` mount is an addition to it.
- **Non-invasive plumbing** — `docker cp`, in both directions: copy in to a
  `create`d-but-never-`start`ed container, copy out of an exited one.
  `docker inspect` shows `Mounts=[]`/`Binds=[]` throughout — `cp` rides the
  daemon API, not the mount table, so it adds nothing beyond the default.
- **Tested** — Docker Desktop for Mac, `desktop-linux` VM. Its file-sharing
  allowlist gates only explicit `-v` mounts, so it does not affect zero-flag
  containers; one Desktop-only quirk observed (DNS proxied via
  `192.168.127.7` rather than Engine's `127.0.0.11`). **Not tested:** a bare
  Linux daemon of the kind CI runs. The findings are Engine-level rather than
  Desktop-specific and should hold there, but that was not independently
  re-verified.

### Podman

[Research ticket](../.scratch/sandbox-canary-nesting/issues/02-podman-default-nesting.md)
· write-up `docs/research/podman-default-nesting.md`, branch
`research/podman-default-nesting` (`2e2f066`)

- **Default sharing** — filesystem: **nothing**, the same structural absence as
  Docker (a canary file was `ENOENT`; `/tmp`, `/home`, `/Users` empty or
  absent). Network: **shared by default** — bridge, NAT, working DNS, outbound
  internet via slirp4netns/pasta. Rootless mode does not change *what* is
  shared, but it changes *ownership resolution* once something is bind-mounted:
  container UID 0 maps 1:1 to the real invoking host user
  (`/proc/self/uid_map`), UIDs 1+ map through `/etc/subuid`, so a host file
  owned by the invoking user reads as root inside. That matters to the sibling
  seeding work: permission checks on a bind-mounted `/run/user/<uid>` socket
  resolve through this mapping, not literal UID equality.
- **Non-invasive plumbing** — `podman cp`, same two-step create-then-copy shape
  as Docker; copy-in before start and copy-out after exit both verified with
  zero bind mounts.
- **Tested** — Podman v6.0.2 rootless, via `podman machine`.

### bubblewrap

[Research ticket](../.scratch/sandbox-canary-nesting/issues/03-bwrap-default-nesting.md)
· write-up `docs/research/bwrap-default-nesting.md`, branch
`research/bwrap-default-nesting` (`f0d9bc4`)

- **Default sharing** — **there is no vendor default.** bubblewrap's own README
  says so: *"bubblewrap is not a complete, ready-made sandbox with a specific
  security policy."* Every namespace and bind decision is an explicit flag, so
  this one never paralleled the container runtimes and was flagged as such
  before the work started. Its own illustrative README example is itself a
  minimal, mostly-read-only reconstruction — closer to the current launcher
  than to a full root bind.
- **Non-invasive plumbing** — `--bind / /` does genuinely nest: a canary at
  `~/.ssh/id_rsa_canary` was unreachable under the current launcher and both
  readable and round-trip writable under it, with `sandbox_detection:
  "bubblewrap"` unaffected (the probe's detection is an ancestor-process-name
  walk over `/proc`, filesystem-independent, and neither invocation uses
  `--unshare-pid`). But full root bind carries a real gap, not a cosmetic one:
  a write to `/etc` fails only with ordinary `Permission denied` — Unix DAC,
  caller-dependent — where the minimal reconstruction's `--ro-bind /etc /etc`
  fails with `Read-only file system`, namespace-enforced regardless of caller.
  The least-bad shape would have been `--ro-bind / /` plus one targeted
  writable bind for the probe's workdir.
- **Tested** — Docker Desktop's `desktop-linux` VM, both invocations, canary
  reachability and fingerprint compared side by side.

### systemd-nspawn

[Research ticket](../.scratch/sandbox-canary-nesting/issues/04-nspawn-default-nesting.md)
· write-up `docs/research/nspawn-default-nesting.md`, branch
`research/nspawn-default-nesting` (`65a95dc`)

- **Default sharing** — **nothing, and it cannot nest on host root at all.**
  `systemd-nspawn -D /` is a hard compiled-in refusal (*"Spawning container on
  root directory is not supported…"*), confirmed empirically and matching the
  man page: nspawn does a full pivot_root-style takeover of the tree it is
  given, so it structurally requires a separate prepared rootfs. Today that
  rootfs is built fresh from a `docker export` of `ubuntu:latest`, related to
  the seeded parent not at all.
- **Non-invasive plumbing** — `--bind=`/`--bind-ro=`, which is vendor-intended
  rather than a workaround: the man page documents no other way to expose a
  host path inside the container's namespace, and the launcher already uses it
  for the report output directory. Extending it to the seeded parent's `$HOME`
  is one more use of the same documented mechanism.
- **Tested** — the same `docker export`-based rootfs the workflow builds, with
  a decoy placed outside it: unreachable by default, reachable once shared via
  `--bind=`, with `container=systemd-nspawn` (the probe's fingerprint fallback)
  correctly set. Test-environment wrinkle, not a property of nspawn: this ran
  nested inside a privileged container inside Docker Desktop's VM, which has no
  host systemd, so `/run/systemd/container` did not populate and `--register=no`
  was needed. The probe treats both signals as equivalent, so it does not
  affect the verdict. **Not tested:** a real Linux host with systemd.

### gVisor

[Research ticket](../.scratch/sandbox-canary-nesting/issues/05-gvisor-default-nesting.md)
· write-up `docs/research/gvisor-default-nesting.md`, branch
`research/gvisor-default-nesting` (`7e26503`)

- **Default sharing** — **no implicit default at all**: 100% explicit via the
  OCI `mounts` array, unlike Docker's auto-attached bridge. `runsc spec`'s own
  generated template has three entries (`/proc`, tmpfs `/dev`, `/sys`), none
  host-facing. Confirmed against gVisor's filesystem documentation (all host
  access is mediated by the gofer, which serves only what `mounts` lists), its
  OCI quick-start, the OCI runtime spec, and empirically by dumping the
  generated `config.json`.
- **Non-invasive plumbing** — one more entry on the same `.mounts` array the
  workflow already edits for the output directory:
  `{"destination":$home,"source":$home,"type":"bind","options":["bind","ro"]}`.
  Identical source and destination keeps the probe's `os.UserHomeDir()`-based
  checks working unmodified. No alternative primitive exists — Docker's own
  `-v` lowers to the same OCI construct.
- **Tested** — verified end-to-end, not merely designed: a decoy SSH key seeded
  on the parent, `runsc run` twice. Without the extra mount the decoy is
  invisible (today's behaviour); with the one added entry it is readable
  byte-for-byte, confirmed via both the probe's report and a direct `cat`.
  `sandbox_detection: "gvisor"` fires correctly either way, via the
  `/proc/version` fallback. Root and the systrap platform are unavailable on
  macOS, so this used Docker Desktop's Linux VM as the disposable stand-in.
- **Two side findings, unrelated to the mounting mechanism.** The launcher's
  gvisor comment claims `/__runsc_containers__` exists under a bare `runsc run`
  and it does not (corrected separately). And the probe's own mount enumerator
  did not surface the gVisor bind mount even though the file behind it was
  demonstrably reachable — a probe bug, tracked as
  [sandbox-probe#7](https://github.com/controlplaneio/sandbox-probe/issues/7),
  and unaffected by retiring this row.

---

## The flag audit: firejail, nono, srt

[Research ticket](../.scratch/sandbox-canary-nesting/issues/06-firejail-nono-srt-flag-audit.md)
· write-up `docs/research/firejail-nono-srt-flag-audit.md`, branch
`research/firejail-nono-srt-audit` (`e5af3a4`)

These three restrict the *same* filesystem by policy rather than swapping in a
fresh rootfs, so the fresh-rootfs bug never applied to them — confirmed here
for the filesystem dimension. What the audit checked instead is whether each
added restriction flag is the vendor's own default or this project's addition.

| Tool | Flag | Verdict |
| --- | --- | --- |
| `srt` | `--settings <file>` | **Vendor default, minimum to run.** srt's README states secure-by-default — network deny-all, filesystem write deny-all, read allow-all — confirmed by running bare `srt` with no settings file present. The policy only widens writes to `$PWD` and `/tmp`, the minimum needed to emit a report. No added narrowing; the row is unchanged. |
| `firejail` | `--net=none`, `--seccomp` | **Project-added.** Bare `firejail -- curl …` has open network and full filesystem read/write, confirmed against firejail's own man page. Same category of error as the container launchers, scoped to network and seccomp only. |
| `firejail` | `--quiet` | Output only; no effect on the boundary. |
| `nono` | `--block-net` | **Project-added.** nono's own `--help`: *"Block outbound network access (allowed by default)."* |
| `nono` | `--allow-cwd`, `--allow <dir>` | **Minimum to run.** nono denies everything with zero flags and will not start non-interactively; these are the smallest grant that lets it run at all, not a narrowing. |
| `nono` | `--silent` | Output only. |

nono's asymmetry is the reason a reason has to be recorded per flag rather than
per runtime: the same tool, two flags, opposite verdicts.

**Tested** — each tool's own documentation plus empirical runs in a disposable
`ubuntu:22.04` container on Docker Desktop's VM.

---

## The four agent-driven harnesses

All four were checked. All four were already correct, for three different
reasons, and **none is changed**. Two of the three reasons are not
interchangeable, which is why each was checked rather than inferred from the
first result.

### claude-sandbox — same process tree

[Research ticket](../.scratch/sandbox-canary-nesting/issues/11-claude-sandbox-nesting.md)
· write-up `docs/research/claude-sandbox-nesting.md`, branch
`research/claude-sandbox-nesting` (`49aaa40`)

Claude Code applies its own sandbox to the shell subprocess in place; no fresh
rootfs is constructed. With 17 real decoys seeded under `$HOME`,
`sensitive_readable_paths` was byte-for-byte identical between
`CLAUDE_SANDBOX=off` and `on` — all 33 entries, every decoy — proving the
sandboxed run is the same process tree on the same filesystem. The sandbox was
genuinely active rather than a no-op: network connectivity dropped from
`["google.com"]` to `[]`, and `sandbox_detection` fired `"seatbelt"` only when
sandboxed. Reads are unrestricted because that is Seatbelt's own default policy
under Claude Code's configuration, not a nesting failure.

**Tested** — macOS, Seatbelt path. **Not tested:** the Linux bubblewrap path.

### codex-sandbox — same process tree

[Research ticket](../.scratch/sandbox-canary-nesting/issues/12-codex-sandbox-nesting.md)
· write-up `docs/research/codex-sandbox-nesting.md`, branch
`research/codex-sandbox-nesting` (`217feb7`)

Same shape, checked separately because `workspace-write` is a different policy
from Claude Code's: all 33 `sensitive_readable_paths` findings identical
between `CODEX_SANDBOX=on` and `off` — that mode does not restrict reads, by
design — while writes are genuinely confined (a `$HOME` write blocked under
`on` with `Operation not permitted`, succeeding under `off`; `/tmp` succeeding
both ways, matching Codex's own `workspace-write [workdir, /tmp, $TMPDIR]`
policy banner). The `"seatbelt"` fingerprint was cross-checked against macOS's
real `sandbox_check()` API rather than taken from Codex's own claim.

**Tested** — macOS, Seatbelt path, codex-cli 0.142.5. **Not tested:** the Linux
bubblewrap+seccomp path.

### gemini-docker — a real, narrower vendor boundary

[Research ticket](../.scratch/sandbox-canary-nesting/issues/13-gemini-docker-nesting.md)
· write-up `docs/research/gemini-docker-nesting.md`, branch
`research/gemini-docker-nesting` (`243c8ca`)

gemini-cli re-execs itself inside a container using *its own* docker
invocation. Reading that source directly (installed `@google/gemini-cli`
0.49.0, cross-checked byte-for-byte against the `v0.49.0` GitHub tag): the
workspace is bind-mounted at its literal host path — no fresh rootfs, so it
genuinely nests — plus a small named allowlist (`$HOME/.gemini`, the temp
directory, conditionally `~/.config/gcloud` and a
`$GOOGLE_APPLICATION_CREDENTIALS` file, both read-only). Full `$HOME` is
deliberately not shared. The probe's decoy targets (`~/.ssh/*`, `~/.aws/*`,
`~/.npmrc`, …) fall outside that allowlist entirely, so an unreachable result
there is a real vendor-default boundary, not a disconnected harness. Widening
it via the stub's `SANDBOX_FLAGS` would test a boundary no ordinary gemini-cli
user has; that variable stays mock-plumbing-only.

**Tested** — vendor source, at a pinned tag. **Not tested:** a live run.
gemini-cli chose Seatbelt over an explicitly requested Docker sandbox on 4 of 4
attempts on macOS, root cause unpinned; the matrix runs this row on
`ubuntu-latest` where Seatbelt does not exist. Side finding, not this project's
to fix: the vendor's bundled `sandbox.md` undersells what is shared, saying
"workspace only" and omitting `.gemini`, tmp and gcloud.

### trae-docker — a real container with an unextendable vendor mount

[Research ticket](../.scratch/sandbox-canary-nesting/issues/14-trae-docker-nesting.md)
· write-up `docs/research/trae-docker-nesting.md`, branch
`research/trae-docker-nesting` (`07b85bf`)

Read trae-agent's own installed source (bytedance/trae-agent, `e839e559`):
`DockerManager.start()` constructs exactly one bind mount, `--working-dir` →
`/workspace`, and nothing else — no `$HOME`, no credential directories, and no
CLI flag or configuration field to add a second. Empirically confirmed with
decoys seeded in `$HOME` and a real `trae-cli --docker-image ubuntu:latest`
run through the stub: the probe's own mount enumeration from inside trae's
container shows exactly the working-directory mount, with zero matches
anywhere under `$HOME`, `.ssh` or `.aws` in the full report. Networking is open
(bridge, real DNS and connectivity) because trae never restricts it, matching
Docker's bare default. This is a genuine container on the real Docker daemon on
the real seeded host, using trae's own unmodified mount logic — correctly
nested by construction. No extension point exists, and forcing one (via
`--docker-container-id` against an externally built container) would
reintroduce exactly the anti-pattern this work exists to remove.

**Tested** — vendor source plus a live containerised run.
