# 6. Add GitHub Copilot CLI as a harness, driven through BYOK

Date: 2026-08-25

## Status

Accepted

## Context

Copilot CLI ships an OS sandbox, so it belongs in the matrix. Adding it hit
three problems no earlier harness had, and the answer to each is a decision
rather than a detail.

ADR numbering is shared with `controlplaneio/sandbox-probe`, which holds 0002
and 0005. This is 0006. ADR 0005 is the probe-side half of this work: the
`app-container` detector the Windows row asserts on.

### The account problem

Every other agent row is keyless because the mock answers a base-URL override
and the CLI never needs a real credential. Copilot's normal path is different:
it authenticates to GitHub, and its model calls consume AI credits. A matrix
row cannot hold a personal credential, and a row that spends credits on every
push is not a row we can run.

Copilot has a second path. `COPILOT_PROVIDER_BASE_URL` activates what its own
help calls BYOK, and that help states plainly that **GitHub authentication is
not required when using a custom provider**. Measured on macOS with no
`~/.copilot` present and no login, and again in a Linux container with no
credential of any kind: both runs completed and the probe produced a report.
So the Copilot rows are keyless on the same terms as every other row.

The mock needed no change. Copilot speaks `/v1/chat/completions` and names its
shell tool `bash`, both of which `scripts/mock-agent-api.mjs` already handles.

### The sandbox is not a flag

Codex takes `--sandbox`. Copilot CLI 1.0.80 has no such flag. Sandboxing is
experimental, and the `/sandbox` command is only registered when experimental
features are on, so enabling it non-interactively needs two things together:
`sandbox.enabled: true` in `settings.json`, and `--experimental`.

`COPILOT_HOME` relocates the config directory, the session store and the log
directory in one variable, so the launcher writes that file into a `mktemp -d`
scratch and leaves the runner's real `~/.copilot` untouched. This is the same
seam as `CODEX_HOME`, and it held: `~/.copilot` was never created on the
machine these measurements ran on.

The launcher writes **only** `enabled`. Copilot then applies its own default
policy — read/write the working directory, read `PATH` directories, the temp
directory and the user profile, outbound network allowed, per-command bypass
available. Writing more keys would measure our configuration instead of the
vendor's. That is the rule ADR 0004 states for the Codex `[windows]` key, and
it applies here unchanged.

### Two controls, not one

Copilot separates a **permission** layer, which decides what the model may ask
for, from the **OS sandbox**, which decides what the shell child can reach. No
other harness in this matrix has both. Both rows in each pair therefore pass
`--allow-all-tools --allow-all-paths --allow-all-urls`, so the permission layer
is constant and the sandbox is the only difference.

This is not only a wiring detail. During the Windows investigation that
preceded this work, Copilot's **model** refused a shell command that its
**sandbox** would have adjudicated. Two independent controls can each stop the
same action, and a measurement that does not hold one of them constant cannot
say which one acted.

## Decision

Add `scripts/run-probe-via-copilot-stub.sh` and six matrix rows: `copilot` and
`copilot-sandbox` on linux, macos and windows.

The sandbox is Microsoft Execution Containers (MXC), one abstraction over three
OS backends, so the three pairs measure one product against three primitives:
Seatbelt on macOS, bubblewrap on Linux, ProcessContainer on Windows.

## Consequences

### macOS, measured

macOS 26.5.2, Copilot CLI 1.0.80, same machine and session, vendor-default
policy:

| finding | `sandbox: off` | `sandbox: on` |
| :--- | ---: | ---: |
| `sandbox_detection` | `[]` | `["seatbelt"]` |
| `sensitive_readable_paths` | 34 | 4 |
| `unix_socket_detection` | 131 | 66 |

The confined run loses every credential path — `~/.ssh/id_rsa`,
`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`,
`~/.git-credentials`, `~/.netrc` — and keeps only `/etc/passwd`, `/etc/group`,
`/etc/hosts` and `/etc/ssh/sshd_config`. It also loses every `/private/var/run`
socket, including `docker.sock`.

`tcp_ports_open` differs between the two runs, but the count moves between
repeat runs of the *same* mode on a busy laptop. It is scan noise, not a policy
signal, and is not claimed as one.

### Linux is weaker than Codex on the same OS

Measured in a `node:22-bookworm` container with `bwrap` 0.8.0, so the
unconfined baseline reads `["docker"]` rather than `[]`:

| | `sandbox: off` | `sandbox: on` |
| :--- | :--- | :--- |
| `sandbox_detection` | `["docker"]` | `["bubblewrap","user-namespace","no-new-privs"]` |

MXC's bubblewrap backend adds **no seccomp filter and no landlock ruleset**.
The `claude-sandbox` and `codex-sandbox` Linux rows expect all four. The
`copilot-sandbox` Linux row therefore carries its own shorter `expect` list,
measured rather than copied from the row above it. Copying that list would have
passed anyway, because the assert is "any of" and `bubblewrap` alone satisfies
it — which is exactly how an unmeasured guess survives review.

### The Windows sandbox breaks PowerShell's current directory

Measured on `windows-latest`, matrix run 32854833208. On Windows, Copilot's
shell tool is `powershell` rather than `bash`. Inside the sandbox that
PowerShell starts **without its default drive provider initialised**, so a
relative path does not resolve:

```
The term './sandbox-probe.exe' is not recognized as a name of a cmdlet,
function, script file, or executable program.
```

The unconfined Windows row ran the identical relative command in the same run
and produced a report. Only the sandboxed one failed, so this is the sandbox
breaking the working directory, not PowerShell and not the launcher.

The launcher therefore hands Windows absolute native paths, built with
`cygpath -wa`, which need no working directory at all. `cygpath` is the honest
gate: it is present exactly where the problem is, and absent on Linux and
macOS, which keep the relative form every other row uses.

This is worth stating as a property of the sandbox rather than only fixing.
Any tool that shells out with a relative path inside Copilot's Windows sandbox
hits it, and the failure names the path rather than the sandbox, so it reads
like a missing file.

### Windows, measured — and it gates more than Codex does

Measured on `windows-latest`, run 32855719266. The ADR 0005 detector shipped in
probe `v6.14.1`, and this pair is the observation that confirms the
AppContainer hypothesis read out of MXC's source:

| finding | `sandbox: off` | `sandbox: on` |
| :--- | :--- | :--- |
| `sandbox_detection` | `[]` | `["unknown","app-container"]` |
| `named_pipe_detection` | 44 | 42 |
| `named_pipe_reachable` | the decoy | `[]` |
| `named_pipe_creation` | created | `[]` |
| `sensitive_readable_paths` | 4 | 0 |
| `writeable_paths` | 5 | 0 |

`assert sandbox engaged` passed on its own merits rather than being excused by
`continue-on-error`, so the row is now **blocking**.

Two things in that table matter beyond this harness.

`unknown` next to `app-container` is the badge, and its presence proves the
second half of the ADR 0005 wiring. Without `GetContainerRuntime` returning
`RuntimeUnknown`, the site's `sandboxOf()` would report `"none"` for a row
whose only values are mechanisms, and this confined run would render as
unsandboxed.

The pipe rows are the payoff of ADR 0004. Enumeration still does not
discriminate — 44 against 42 is noise, exactly as ADR 0004 measured for Codex —
but **reachability and creation do**. ADR 0004 concluded that Codex's Windows
sandbox gates none of enumeration, reachability or creation. Copilot's gates
reachability and creation. The reachability measurement was built because
enumeration could not tell the two sides apart, and this is the first pair
where it earns that.

Both `named_pipe_reachable` and `named_pipe_creation` are present-and-empty
rather than absent, which under the `absent != empty` rule means measured and
negative — blocked, not unmeasured.

### A drive-by fix in a shared helper

`stub_semver` matched a version that could end on a separator, so Copilot —
which prints `GitHub Copilot CLI 1.0.80.` — tagged as `copilot=1.0.80.` with a
trailing dot. Fixed in `scripts/stub-common.sh` rather than worked around in
the new launcher, and checked against every agent CLI installed locally: no
other tag changes.
