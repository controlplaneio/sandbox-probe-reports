# 4. Windows: reachability over visibility, and what Codex's sandbox actually does

Date: 2026-08-25

## Status

Accepted

Numbering continues the sequence the two repositories share: 0001 (client-side
site, here), [0002](https://github.com/controlplaneio/sandbox-probe/blob/main/docs/adr/0002-seed-ipc-and-process-targets.md)
(the seed/target registry, with the probe), 0003 (canary nesting, here).

## Context

The probe has enumerated Windows named pipes since July, and the matrix has had
two Windows rows since. Neither has ever produced a comparison.

On 2026-08-24 the reason was measured rather than reasoned about, on a Windows 11
host running Codex CLI 0.149.1 and on a GitHub `windows-latest` runner.

### Enumeration does not discriminate

Confined by Codex's Windows sandbox versus unconfined, same machine, same
session:

| host | pipes confined | pipes unconfined |
| --- | --- | --- |
| Windows 11 VM | 57 | 57 |
| `windows-latest` runner | 40 | 40 (unconfined `direct` baseline: 38) |

Identical both times. A restricted token changes **access checks**; enumerating
`\\.\pipe\*` is a directory read, which it does not gate. So
`named_pipe_detection` cannot tell a sandboxed Windows agent from an unsandboxed
one, and never could.

### Both Windows rows were unconfined

`direct` and `opencode`. There was no confined column for anything to be
compared against, so even a discriminating measurement would have had nothing to
say.

### The probe could not see the sandbox

A demonstrably confined run emitted `sandbox_detection=[]`. Every branch of the
detector is `/proc`-shaped, so `SandboxTask.Run` returned nothing on Windows.

## Four undocumented constraints on Codex's Windows sandbox

All reproduced, and none of them documented by the vendor at the time of
writing. Evidence: CI run
[32724090747](https://github.com/controlplaneio/sandbox-probe-reports/actions/runs/32724090747),
an A/B/C comparison on `windows-latest`.

1. **The `--sandbox` flag is inert without a config key.** Codex reports
   `sandbox: read-only` whatever is passed on the command line, and rejects every
   command under it — a bare `echo` included. `[windows] sandbox = "unelevated"`
   in `config.toml` flips the same invocation to `workspace-write`. Case C of the
   run above is the control: same flag, no key, blocked by policy, no report.
2. **The sandbox cannot be built from a token with no Logon SID.** Under a
   service context it fails with `Logon SID not present on token`.
3. **Codex blocks on stdin with no console.** It must be given `NUL`/`/dev/null`.
4. **Under a batch logon the child dies at `0xC0000142`**
   (`STATUS_DLL_INIT_FAILED`) — a restricted token with no usable window station.
   `sandbox_private_desktop` does not change it. An interactive session works,
   and GitHub runners are interactive (`>console runneradmin 2 Active`), which is
   why this is viable in CI at all.

Constraint 1 is the one with teeth for this repository: a Windows row built on
the flag alone reports itself as sandboxed, runs read-only, and produces no
report. That is worse than a red row, because it looks configured.

## Decision

### 1. Reachability is the measurement; visibility is context

`named_pipe_detection` stays, as inventory. The scored question becomes whether
a pipe can be **opened**, proven by a token round trip.

### 2. Reachability is only ever measured against the probe's own decoy

Opening a real service's pipe is **not passive**: it consumes a server instance,
delivers a connection event, and can hang a badly written server. This runs on
real developers' laptops.

Probing the catalogue names is the tempting alternative and it is unsafe. At scan
time `\\.\pipe\docker_engine` is either our decoy or a live Docker Desktop, and
the scan is a different process from the seeder with no way to tell. Making it
tell would mean reading the seed record — putting a *safety* property behind a
filesystem read the sandbox under test may block. Exactly backwards.

So `ReachPipeName` is a fixed private name that is deliberately not a catalogue
entry, and a per-pid control name nothing ever serves provides the calibration.

### 3. Reading a foreign pipe's DACL is not a passive alternative

It was considered and rejected on Microsoft's own documentation: the access check
happens on the open, and the only way to obtain a `READ_CONTROL` handle to a
foreign pipe by name is to open the client end — which is a connect. Microsoft's
guidance for reading a pipe's security descriptor is handle-based
`GetSecurityInfo`, on a handle you already hold.

### 4. `ImpersonateNamedPipeClient` is never implemented

It is the pipe-squatting attack itself — stealing a connecting victim's token.
The safe proxy for "can this sandbox squat a name" is whether
`CreateNamedPipe` succeeds, which is what `named_pipe_creation` reports.

### 5. The Windows `expect` asserts a mechanism, never a tool name

The probe reads `IsTokenRestricted()` on its own token. That is kernel-attested,
and it cannot say which sandbox applied it — Chromium's renderer and `psexec -l`
produce restricted tokens too.

Deliberately **not** keyed on the sandbox's visible effects. Inside the sandbox
`BUILTIN\Administrators` is demoted to "use for deny only" and privileges
collapse to `SeChangeNotifyPrivilege` alone — and both are exactly what an
ordinary non-elevated administrator's UAC split token looks like. A detector
keyed on either would report every unconfined Windows desktop as sandboxed,
including the `direct` baseline row whose whole job is to be the unconfined
comparison. Integrity level is excluded on the measurement, not on principle: it
is High on both sides.

Asserting a tool name where only enforcement is observable is what kept
`srt (linux)` red for three weeks.

## Consequences

Windows gains a confined row that asserts on something the probe can observe, and
the named-pipe capability starts producing evidence rather than a name list that
is identical either side of the boundary.

The `codex-nono` rows stay red and non-blocking for an unrelated reason recorded
at the row: nono 0.74.0 does not grant read on the directory holding the `codex`
binary, so codex exits 127 before it starts. nono names `--read <dir>` as the
fix; taking it would make the row measure our configuration rather than the
published profile.

Two things remain unverified and are stated rather than papered over. Codex's
**`elevated`** mode may work by launching as a separate account rather than by
`CreateRestrictedToken`, in which case this detector reports nothing — a silent
false negative needing the same token comparison already done for `unelevated`.
And if it does turn out to be account-based, "running as a different user" must
**not** become a signal: that is indistinguishable from `runas`, a service
account or a CI agent, and is a worse false-positive generator than the one this
design exists to avoid.

The throwaway workflow that produced the evidence above
(`.github/workflows/windows-sandbox-probe.yaml`, branch
`probe/windows-sandbox-viability`) is deleted with this ADR. The run it produced
is linked above and is the durable record.
