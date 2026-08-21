# 3. Canary nesting, and the criterion for a comparable harness

Date: 2026-07-31

## Status

Accepted

Numbering continues the sequence the two repositories shared before the split:
0001 (client-side site, here) and
[0002](https://github.com/controlplaneio/sandbox-probe/blob/main/docs/adr/0002-seed-ipc-and-process-targets.md)
(the seed/target registry, which stays with the probe).

## Context

The matrix claims to measure what a sandbox does out of the box. For a third of
its rows it measured what this project told the sandbox to do.

### The canary model

A sandbox comparison is only meaningful if the thing being reached for exists
outside the sandbox and the sandbox is genuinely inside the host that holds it:

1. **Seed the parent.** Canaries are planted on the real, unconfined host, by
   the same seeder, identically before the baseline run and every sandbox run.
2. **Launch the sandbox as a genuine child of that seeded parent** — not as a
   freshly constructed environment with no relationship to it.
3. **Ask whether the process inside can reach what exists outside.**

**Canaries are never seeded inside the sandbox.** That would test whether the
sandbox's own environment happens to contain artefacts, which is not the threat
model: a real attacker inside a real sandbox is trying to reach *out*, not
finding things planted *in*. It also flatters every result — an environment
built moments earlier by the harness contains exactly what the harness put
there. The sandbox is tested as the vendor ships it: nothing artificially
opened, nothing artificially closed.

### What that model exposed

Five rows in the sandbox family — docker, podman, bwrap, nspawn and gvisor,
driven directly with no agent — were never children of the seeded parent. Each
constructs a fresh root filesystem: the container runtimes from a pulled image,
nspawn and gvisor from a `docker export` of one, bwrap by reassembling a
minimal root that omits `/home` entirely. They are siblings that never had a
route to the parent. A fresh environment correctly showing no decoys is not
evidence that anything was blocked; there was nothing there to block.

Separately, five audits each found the same class of error in the launch flags,
each time by checking a runtime's documented default against what the launcher
passed: the container runtimes and gvisor launched with networking disabled,
which is *stricter* than their real default of a working bridge with DNS and
egress; firejail launched with networking disabled and a seccomp filter added,
where bare firejail has open network and full filesystem read/write; nono
launched with outbound network blocked, where nono's own help text says network
is allowed by default. Every one made a sandbox look tighter than it ships, and
a reader comparing rows would have attributed our flag to the vendor's posture.

### Why better flags do not fix the five

The obvious repair — add sharing flags so the five nest properly — is the wrong
one. **Any** sharing flags this project's own launcher adds are its own choice
too. "Did the sandbox block what we chose to expose?" is circular no matter
which flags get picked; a different maintainer picking different flags would
publish a different verdict about the same runtime, and both would be
defensible. The per-runtime research confirms the mechanism exists in every
case (`docker cp`, `podman cp`, `--bind=`, an OCI `mounts` entry, `--ro-bind /
/`) — the problem is not that nesting is impossible, it is that nobody outside
this project would be deciding what it shared.

## Decision

### 1. The canary model is the methodology

Seed the parent, launch as a genuine child, ask whether the inside can reach
the outside. Never seed inside a sandbox.

### 2. The comparability criterion

> **A harness belongs in the baseline-normalized matrix only when someone other
> than this project decided its configuration.**

An external decision-maker means an agent vendor choosing its own sandbox
settings, or a declared, externally-authored policy profile. It does not mean a
setting this project chose because it seemed reasonable. Where the harness must
pass flags anyway, each is declarable under one of three reasons and nothing
else: **vendor-default** (reproduces what the tool does with no flags, and
exists only because the invocation shape demands it explicitly),
**minimum-to-run** (without it the tool will not start or cannot execute the
probe), **output-only** (affects logging or verbosity, never the boundary).

Applying it to what exists today:

- **The four agent-driven harnesses are admitted.** The vendor decides. Claude
  Code and Codex apply their own sandbox to the same process tree; gemini-cli
  and trae-agent construct their own containers with their own mount logic.
  Three are correct for different reasons and the fourth — gemini's workspace
  plus a small named allowlist — is a real vendor boundary that happens to be
  narrower than `$HOME`.
- **srt is admitted, unchanged.** It matches its vendor default exactly:
  secure-by-default, with the settings file widening writes only to the working
  directory and temp, which is minimum-to-run.
- **firejail and nono are admitted once the project-added flags are gone.**
  Both restrict the real host filesystem by policy rather than swapping in a
  fresh one, so both genuinely nest, and both apply a vendor policy underneath.
  firejail's `--net=none` and `--seccomp` and nono's `--block-net` are
  undeclarable under the vocabulary above and are removed. nono's `--allow-cwd`
  and `--allow <dir>` **stay**: nono denies everything with zero flags and will
  not start non-interactively, so they are minimum-to-run, not a narrowing.
  firejail is the interesting boundary case — it takes project-added flags the
  way the containers do, and removing them is exactly what moves it across the
  criterion.
- **The five generic runtimes are excluded on circularity, not
  misconfiguration.** There is nothing wrong with
  [docker](../nesting-evidence.md#docker),
  [podman](../nesting-evidence.md#podman),
  [bwrap](../nesting-evidence.md#bubblewrap),
  [nspawn](../nesting-evidence.md#systemd-nspawn) or
  [gvisor](../nesting-evidence.md#gvisor) — each entry records the runtime's
  real default sharing behaviour and the non-invasive plumbing that would have
  nested it. There is no non-circular way for *this project* to configure them,
  because with no agent and no declared profile there is no external decision
  to observe. That is why this is a retirement rather than a rewrite.

### 3. The evidence is published, not asserted

[`docs/nesting-evidence.md`](../nesting-evidence.md) records, for each of the
five retired runtimes, its real default sharing behaviour, what non-invasive
plumbing would have looked like, and what was actually tested and on what —
plus the firejail/nono/srt flag audit and all four agent-harness
verifications, each with the gaps it did not reach. It is a single index, and
no unmerged research branch is needed to follow any verdict in it.

Each corrected flag cites its evidence: firejail's `--net=none`/`--seccomp` and
nono's `--block-net` from
[the flag audit](../nesting-evidence.md#the-flag-audit-firejail-nono-srt);
`--network=none` on the container runtimes from
[Docker](../nesting-evidence.md#docker) and
[Podman](../nesting-evidence.md#podman).

### 4. The agent-driven harnesses are left alone

All four were verified and none is changed. In particular gemini's narrower
boundary is not widened: injecting a `$HOME` mount through the stub's
`SANDBOX_FLAGS` would test a boundary no ordinary user of that tool has, and
trae exposes no extension point at all — forcing one would reintroduce the
harness-builds-its-own-environment anti-pattern this decision removes.

### 5. Retired identities keep their published history

Existing time-series data for retired identities stays on the data branch.
Deleting it would rewrite published history, and it is a truthful record of
what those runs reported at the time. The site stops plotting an identity that
no longer receives runs, rather than showing a line that silently ends: the
rule that a new harness joins with no code change implies its inverse, that a
departed one leaves the same way.

## Consequences

- **The matrix shrinks and the remaining rows mean more.** Nothing about the
  cell states, capability categories or the exposure scale changes; rows leave,
  the arithmetic on the rest is untouched.
- **firejail and nono will look more exposed** once their added flags go. That
  is the honest result, not a regression. If dropping a flag also changes the
  detected enforcement mechanism, that is a finding about the tool to be
  recorded, not a fingerprint assertion to quietly adjust.
- **A reviewer can judge the methodology** from this record and the evidence
  index rather than taking it on trust.
- **The criterion has to be applied to future rows**, not just remembered. A
  test over the launcher asserts that every flag passed to a runtime is
  declared with one of the three reasons, so an undeclarable flag fails in the
  pull request that adds it rather than in a later audit.

### Proposing a new row

A contributor can decide this without asking a maintainer. Three questions:

1. **Who decided this harness's configuration?** If the answer is "we did, in
   our launch script", the row does not qualify — no choice of flags fixes
   that. If it is an agent vendor's own sandbox, or a declared policy profile
   authored outside this project, it qualifies.
2. **Is it a genuine child of the seeded parent?** If the harness constructs a
   fresh root filesystem that has no route to the seeded host, its results
   cannot distinguish "blocked" from "never reachable". A vendor that
   constructs its own container with its own mount logic is fine — that is the
   vendor's boundary. A container this project constructs is not.
3. **Can every flag you pass be declared vendor-default, minimum-to-run, or
   output-only?** If a flag narrows the boundary beyond what the tool does with
   no flags, it is testing a policy nobody shipped. Remove it, or the row does
   not qualify.

Three yeses and the row belongs in the matrix. Any no, and the finding it would
produce is about this project rather than about the sandbox.

## Related

- **[ADR 0002 — the seed/target registry](https://github.com/controlplaneio/sandbox-probe/blob/main/docs/adr/0002-seed-ipc-and-process-targets.md)**,
  in the probe repository, where it stays because it decides the probe's own
  registry shape. The two compose: 0002 decides *what* gets seeded on the
  parent and how to seed it safely on a real machine; this ADR decides whether
  a sandboxed run can *reach* what is seeded, and which harnesses are worth
  asking that about. The matching one-line back-reference to this ADR lands in
  0002 as a follow-up in that repository.
- **[The canary-nesting evidence index](../nesting-evidence.md)** — the
  per-runtime findings behind every verdict above.
- **[The `sandbox-canary-nesting` wayfinder map](../../.scratch/sandbox-canary-nesting/map.md)**
  — how the finding was reached, ticket by ticket.
- **[The `profile-attestation` wayfinder map](../../.scratch/profile-attestation/map.md)**
  — spawned directly from the circularity finding here: the declared-versus-actual
  comparison is what makes an externally-authored decision observable, and is
  the route by which a runtime with no agent could earn a row.
