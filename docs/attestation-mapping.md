# Declared grant → observing finding

How a declared nono grant is matched to the probe finding that observes it, so a
contributor can extend the mapping when either side gains a field. The
vocabulary (attestation, drift, coverage, modifier, caveat, undeclarable
finding) is defined in [`CONTEXT.md`](../CONTEXT.md); the code is
[`scripts/attest.mjs`](../scripts/attest.mjs) and its fixtures are under
[`tests/fixtures/attestation/`](../tests/fixtures/attestation/).

The declared side is always the **resolved capability set** — nono's capability
manifest — never the authored profile. Groups, aliases, inheritance and
protection bypasses are already expanded there; diffing the authored profile
would mean reimplementing nono's resolver.

In a real run ([`scripts/attest-profile.sh`](../scripts/attest-profile.sh)) that
document is `policy.json` in the installed pack —
`${NONO_CONFIG:-~/.config/nono}/packages/<namespace>/<name>/policy.json` — which
is the artifact `nono run --profile` actually applies. `nono profile show` prints
the same thing for humans but not as JSON. If the pack layout moves, the script
fails naming the path and listing what it did find rather than attesting against
something else.

## The mapping

Each row is one **declared unit**: one thing the capability set claims, and the
one finding type that can confirm it. Polarity `absent` marks an *inverted*
declaration — one that claims un-reachability, so it is delivered by the finding
being missing.

| Capability-set field | Declared unit id | Finding type | How an observation is matched |
| --- | --- | --- | --- |
| `filesystem.grants[].access: read` / `readwrite` | `filesystem.read:<path>` | `sensitive_readable_paths` | path equality; a `directory` grant also covers everything beneath it, `~` expanded against the run's home |
| `filesystem.grants[].access: write` / `readwrite` | `filesystem.write:<path>` | `writeable_paths` | as above |
| `filesystem.unix_socket*` (six fields) | `filesystem.<field>:<path>` | `unix_socket_detection` | `_dir` covers direct children only, `_subtree` the whole subtree, the bare field an exact path. Only when mediation is on — see modifiers |
| `network.mode: "blocked"` | `network.block` | `external_host_connectivity` | inverted: attested by *no* egress under the profile while the baseline had some |
| `network.allow_domains[]` | `network.allow_domains:<domain>` | `external_host_connectivity` | exact host, or suffix when the domain starts with `.` (which also covers the bare apex) |
| `network.ports.*[]` | `network.ports.<list>:<port>` | `tcp_ports_open` | port equality, over every port list the manifest carries |
| `credentials[].source: env://NAME` | `credentials:<name>` | `env_secret_detection` | the finding's `env_key` equals `NAME` |
| `process.process_info_mode` | `process.process_info_mode` | `process_detection` | `allow_all` is a grant; `isolated` and `allow_same_sandbox` are inverted — attested by no process being visible while the seeded baseline saw one |

A readwrite grant is **two** units, and they can land in different drift classes:
the write half may be delivered while the read half was never provable.

Deliberately *not* folded in, each for a reason that is not obvious from the
field name:

- **`external_host_dns_resolution`** — carries resolved IPs, which cannot be
  matched back to a declared domain. The connectivity finding already implies
  resolution, because the probe only tries to connect to a host it resolved.
- **`parent_process_detection`** — the run's own ancestry, which no
  process-info mode claims to hide. Folding it in the way the exposure matrix
  does would turn a delivered restriction into a false gap.
- **`udp_ports_open`** — nono's port declarations are TCP-only; there is nothing
  on the declared side to diff against.
- **`filesystem.deny`** — declares un-reachability of a path already inside a
  broader grant. A denied path that turns up reachable already falls out as a
  **gap**, which is the security-relevant verdict, so it gets no unit of its own.
- **`proxy_detection`** — nono's proxy mode injects *custom-named* env vars
  (`base_url_env_var`, `ca_env_vars`), and whether any of them land in the
  standard `HTTP_PROXY` family the probe scans is unconfirmed. Left unmapped
  rather than guessed.

## Named as unattested

Declared, and nothing in the probe's finding model observes the category at all.
These are reported explicitly with a reason, never folded into a match, and they
lower **coverage** — silence must never read as a pass.

| Capability-set field | Declared unit id | Why nothing observes it |
| --- | --- | --- |
| `process.signal_mode` | `process.signal_mode` | no "can I signal PID X" check exists; process findings observe visibility, not signalling |
| `process.ipc_mode` | `process.ipc_mode` | no POSIX IPC/semaphore finding type |
| `allow_gpu` | `allow_gpu` | no GPU-device reachability finding |
| `allow_launch_services` | `allow_launch_services` | no LaunchServices finding |
| `resources.memory_bytes`, `resources.max_processes` | `resources.<field>` | the probe never tries to exhaust a ceiling |
| `network.endpoints[].rules` | `network.endpoints:<host>` | host reachability is observed; HTTP method-and-path filtering is not. The host half still counts as declared, so egress to it is never a gap |
| `process.allowed_commands` / `blocked_commands` | `process.commands` | exec-time gating ("may this command run") is a different axis from what is visible once running |
| `environment.allow_vars` / `deny_vars` / `set_vars` | `environment.filtering` | `env_secret_detection` reports only the secret-shaped subset, so it cannot say whether an allow/deny list was applied. `environment_detection` is host kernel/OS release — a confusingly similar name for an unrelated thing |
| `network.mode` (anything but `blocked`) | `network.mode` | says how egress is mediated, not whether any destination is reachable; the domains and ports under it are the grants |

`unsafe_macos_seatbelt_rules` is the one category with no single answer: a raw
Seatbelt S-expression maps to whatever finding its rule happens to affect, so it
would need case-by-case analysis per profile. No unit is emitted for it today.

## Excluded by design

Declared by nono, and deliberately **not** named as unattested, because both run
outside the sandbox boundary a scan measures: no probe finding could ever
observe them, so listing them would advertise a gap that cannot be closed.
Recorded in `EXCLUDED_DECLARATIONS` in `scripts/attest.mjs`.

- `hooks` / `session_hooks` — host-side scripts, run with host privileges
  outside the sandbox.
- `open_urls` — supervisor-mediated URL opening; the supervisor acts, not the
  sandboxed child.

`rollback` / `undo` are snapshot bookkeeping rather than reachability grants, so
they get no unit either.

The mirror image — findings nono has nothing to declare for, excluded from the
diff and never gaps — is `UNDECLARABLE`: mount topology, hostname and UID/GID
context. nono mediates by policy and never swaps a namespace or a rootfs.

## Modifiers and caveats

Neither is a grant, and neither is a drift class.

- **`linux.af_unix_mediation`** (modifier) — opt-in, so absent means off. With
  it off the six socket grants are not enforced at all: every socket-derived
  result becomes unattested carrying the modifier, never a gap and never an
  overclaim, because an unmediated socket surface is not a policy failure.
- **`process.exec_strategy: "supervised"`** (caveat) — a supervisor may elevate
  capabilities mid-run beyond the static declarations, so a point-in-time scan
  may under-report reach. It qualifies the whole reading, changes no verdict and
  moves no coverage.

## nono's published schema is stale — read the struct, not the schema

Ground truth for this mapping is nono's Rust struct and its authoring guide, not
its checked-in JSON Schema, because the schema is behind the implementation in
ways that would silently break the mapping:

- `crates/nono-cli/data/nono-profile.schema.json` declares `FilesystemConfig`
  with `additionalProperties: false` and **omits all six `unix_socket*` fields**
  — `unix_socket`, `unix_socket_bind`, `unix_socket_dir`, `unix_socket_dir_bind`,
  `unix_socket_subtree`, `unix_socket_subtree_bind` — which
  `crates/nono-cli/src/profile/mod.rs` and `docs/cli/features/profile-authoring.mdx`
  both define and use. A profile using them fails validation against nono's own
  schema.
- `crates/nono/schema/capability-manifest.schema.json` (version `0.1.0`, the
  resolved side, and the source its Rust types are generated from) carries only
  `filesystem` / `network` / `credentials` / `process` / `rollback` /
  `resources`. It has no `linux.af_unix_mediation`, no `unix_socket*`, no
  `environment`, no `allow_gpu` / `allow_launch_services`. It is
  `additionalProperties: true` pending 1.0 stabilisation, so a manifest may
  legitimately carry all of them regardless.

This layer therefore reads fields the published schema does not list, using the
authored-profile names where the manifest schema is silent. Upstreaming a schema
fix would be a courtesy; it is not a prerequisite here, and the mapping must not
be "corrected" to match the schema. The finding is recorded in the research
behind this mapping, not just here.

Two further schema-versus-reality notes for whoever extends this:

- The manifest's `PortConfig` names `connect`, `bind`, `localhost` and
  `localhost_range`; the authored profile says `open_port` / `listen_port`. The
  code iterates whatever port lists a manifest carries rather than naming them,
  so a rename costs nothing — but `localhost_range` is a *range*, not a port,
  and is not handled today.
- `network.dns` exists only at the resolved layer; there is no authoring-level
  field for it.

## Extending the mapping

When either side gains a field:

1. Decide which of the three lists above it belongs in — mapped, unattested, or
   excluded by design. Unattested is the default when in doubt: it is honest and
   it shows up in coverage. Excluding is a stronger claim (nothing inside a
   sandbox could observe it, ever) and needs the reason written down.
2. If it is mapped, add the unit in `declaredUnits()` with a `kind` and a
   matcher in `COVERS`, and set `polarity: "absent"` if the declaration is an
   inverted one. Set `declares` even when there is no `findingType`, so the
   declaration still suppresses gaps for what it covers.
3. Extend a fixture under `tests/fixtures/attestation/` with the real document
   shape — a real capability manifest, real probe reports — and add the expected
   drift class to the table in `scripts/attest.test.mjs`. Fixture realism is
   what stops the tests passing against a format the tools do not emit.
4. Update the tables here in the same change. Coverage arithmetic is derived
   from the units, so an undocumented unit silently moves a published fraction.
