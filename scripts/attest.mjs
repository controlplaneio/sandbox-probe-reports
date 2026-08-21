// Profile attestation: diff a *declared* nono capability set against what the
// probe *observed*, and say how much of the declared surface was attestable at
// all. See CONTEXT.md ("Attestation" and the drift classes) and spec
// controlplaneio/sandbox-probe#4. The declared-grant-to-finding mapping — every
// row below, what is unattested and why, what is excluded by design, and nono's
// own stale published schema — is docs/attestation-mapping.md.
//
// Pure function over three documents — a resolved capability set, the report
// from a scan under that profile, and the same-host seeded unconfined baseline.
// No nono binary, no network, no side effects: everything stateful (profile
// fetch, Sigstore, pack install, the sandboxed run) is glue outside this file.
//
// The declared side is the *resolved* capability set (nono's capability
// manifest), never the authored profile: groups, aliases and bypasses are
// already expanded there, and re-implementing nono's resolver is not the job.

// The two filesystem axes this layer observes today.
const FS_FINDING = { read: "sensitive_readable_paths", write: "writeable_paths" };
// A readwrite grant is two declarations: both findings are needed to confirm it.
const ACCESS_UNITS = { read: ["read"], write: ["write"], readwrite: ["read", "write"] };

// Egress: `external_host_connectivity` alone, not folded with DNS. The probe only
// records connectivity for a host it *first resolved*, so the connectivity finding
// already means "resolved and connected"; `external_host_dns_resolution` carries
// resolved IPs, which cannot be matched back to a declared domain.
const EGRESS_FINDING = "external_host_connectivity";
// Ports: TCP only. nono's port declarations are TCP-only (no UDP field anywhere in
// its schema), so `udp_ports_open` has nothing on the declared side to diff against.
const PORT_FINDING = "tcp_ports_open";

// Sockets: nono's six pathname AF_UNIX grant fields, one per (scope, mode) pair.
// Only pathname sockets are grantable — abstract-namespace ones never are, and the
// probe reports paths, so the mode half is a label: the probe sees that a socket is
// reachable, not whether it connected or bound.
const SOCKET_FINDING = "unix_socket_detection";
const SOCKET_GRANTS = {
  unix_socket: ["file", "connect"],
  unix_socket_bind: ["file", "connect+bind"],
  unix_socket_dir: ["dir-children", "connect"],
  unix_socket_dir_bind: ["dir-children", "connect+bind"],
  unix_socket_subtree: ["dir-subtree", "connect"],
  unix_socket_subtree_bind: ["dir-subtree", "connect+bind"],
};

// Credentials: nono declares each credential's secret by source URI, and only
// `env://NAME` puts it in the child's environment — the half the probe observes.
// The probe emits one `env_secret_detection` finding *per* secret-shaped variable
// (the variable name and why it matched, never the value), so this axis arrives as
// several object-valued findings rather than one list-valued one.
const CRED_FINDING = "env_secret_detection";

// Process visibility: `process_detection` only. `parent_process_detection` is the
// run's own ancestry, which a process-info mode never claims to hide, so folding it
// in the way the exposure matrix does would poison the verdict.
const PROCESS_FINDING = "process_detection";

// `process.exec_strategy: "supervised"` is the one strategy that supports capability
// elevation: a supervisor may grant access mid-run beyond the static declarations, so
// a point-in-time scan may under-report reach. A caveat on the attestation, never a
// drift class and never a per-unit verdict — nothing observed is any less true.
const ELEVATION = "runtime-capability-elevation";
const ELEVATION_REASON =
  "process.exec_strategy is 'supervised' — a supervisor may elevate capabilities mid-run, so a point-in-time scan may under-report what was reachable";
const ENV_SOURCE = /^env:\/\/(.+)$/;
const NOT_FROM_ENV =
  "credential is not sourced from the environment — nothing here observes where it comes from";

// AF_UNIX mediation is opt-in (`linux.af_unix_mediation`), so absent means off. With
// it off the socket grants are not enforced at all, whatever they say: socket results
// are then a *modifier* on the reading, never a policy verdict. Nothing socket-derived
// may be a gap or an overclaim under it — an unmediated surface is not a failure.
const MEDIATION_OFF = "socket-mediation-disabled";
const UNMEDIATED_REASON =
  "linux.af_unix_mediation is off — socket grants are not enforced, so nothing observed here reads as policy";
const socketMediation = (cs) => cs.linux?.af_unix_mediation ?? "off";

// Declared by nono and deliberately *not* named as unattested: both run outside
// the sandbox boundary a scan measures — a hook is a host-side script with host
// privileges, and URL opening is the supervisor's own action, not the child's. No
// finding inside a sandbox could ever observe either, so calling them unattested
// would advertise a probe gap that cannot be closed. See
// docs/attestation-mapping.md.
export const EXCLUDED_DECLARATIONS = {
  hooks: "host-side hook scripts run outside the sandbox boundary — nothing inside a scan can observe them",
  session_hooks: "session lifecycle scripts, host-side and outside the boundary, same as hooks",
  open_urls: "supervisor-mediated URL opening — the supervisor acts, not the sandboxed child",
};

// Findings nono has nothing to declare for by design — it mediates by policy and
// never swaps a namespace or a rootfs. Excluded from the diff entirely: these can
// never be gaps, however reachable they are.
export const UNDECLARABLE = [
  "mounted_volumes_detections",
  "hostname_detection",
  "user_context_detection",
];

// How an undeclared observation names itself, per finding type; paths otherwise.
const GAP_FIELD = {
  [EGRESS_FINDING]: (host) => ({ host }),
  [CRED_FINDING]: (secret) => ({ envKey: secret.env_key }),
};

const NO_FINDING = "no probe finding observes this category";
const NOT_MAPPED = "not yet mapped in this layer";

const trimSlash = (p) => p.replace(/\/+$/, "") || "/";
const expandHome = (p, home) => (home && p.startsWith("~") ? home + p.slice(1) : p);

// nono grants use `~` and may be recursive directories; the probe reports absolute
// expanded paths. Without the home expansion every `~` grant reads as a false
// overclaim, which is the one thing this whole design exists to avoid.
function coversPath(unit, path) {
  const g = trimSlash(unit.path);
  const p = trimSlash(path);
  return g === p || (unit.type !== "file" && p.startsWith(g === "/" ? "/" : `${g}/`));
}

// A socket grant is a file, a directory's *direct children* only, or a whole subtree —
// nono keeps those apart, so a socket one level deeper than a `_dir` grant is genuinely
// undeclared and must fall out as a gap rather than be swallowed by the directory.
function coversSocket(unit, path) {
  const g = trimSlash(unit.path);
  const p = trimSlash(path);
  if (unit.scope === "file") return g === p;
  const prefix = g === "/" ? "/" : `${g}/`;
  if (!p.startsWith(prefix)) return false;
  return unit.scope === "dir-subtree" || !p.slice(prefix.length).includes("/");
}

// A leading dot is nono's suffix wildcard (`.githubusercontent.com` covers
// `raw.githubusercontent.com` and the bare apex); anything else is exact.
const coversDomain = (unit, host) =>
  unit.domain.startsWith(".")
    ? host === unit.domain.slice(1) || host.endsWith(unit.domain)
    : host === unit.domain;

// One matcher per declared-unit kind: does this observed value satisfy the unit.
const COVERS = {
  path: coversPath,
  socket: coversSocket,
  domain: coversDomain,
  port: (unit, port) => unit.port === port,
  env: (unit, secret) => unit.env === secret.env_key,
  any: () => true,
};
const covers = (unit, value) => COVERS[unit.kind](unit, value);

const findingsOf = (report, ft) => report?.findings?.filter((f) => f.findingType === ft) ?? [];
const finding = (report, ft) => findingsOf(report, ft)[0];
// One finding may carry a list of observations (paths, hosts, ports) or be one
// observation in its own right, repeated per finding (env secrets). Both flatten
// to the same thing: every value observed for this finding type.
const observed = (report, ft) =>
  findingsOf(report, ft).flatMap((f) => (Array.isArray(f.value) ? f.value : [f.value]));

// One declared unit per thing the capability set claims. Units with a findingType
// are attestable; the rest carry the reason nothing here observes them and are
// reported as unattested rather than quietly dropped (silence must not read as a
// pass, and must never inflate coverage).
function declaredUnits(cs, home) {
  const units = [];
  const push = (id, u) => units.push({ id, ...u });

  for (const g of cs.filesystem?.grants ?? []) {
    for (const access of ACCESS_UNITS[g.access] ?? []) {
      push(`filesystem.${access}:${g.path}`, {
        category: "filesystem",
        kind: "path",
        access,
        declaredPath: g.path,
        path: expandHome(g.path, home),
        type: g.type ?? "directory",
        declares: FS_FINDING[access],
        findingType: FS_FINDING[access],
      });
    }
  }
  const mediated = socketMediation(cs) === "pathname";
  for (const [field, [scope, mode]] of Object.entries(SOCKET_GRANTS)) {
    for (const path of cs.filesystem?.[field] ?? []) {
      push(`filesystem.${field}:${path}`, {
        category: "filesystem",
        kind: "socket",
        scope,
        mode,
        declaredPath: path,
        path: expandHome(path, home),
        declares: SOCKET_FINDING,
        // Unmediated, the grant is unenforced: unattested, carrying the modifier and
        // the reason, rather than an overclaim the profile never had a chance to keep.
        ...(mediated
          ? { findingType: SOCKET_FINDING }
          : { modifier: MEDIATION_OFF, reason: UNMEDIATED_REASON }),
      });
    }
  }

  // ponytail: filesystem.deny declares *un*reachability, not a grant. A denied
  // path that turns up reachable already falls out as a gap, which is the
  // security-relevant verdict; give deny its own class only if that stops holding.

  const n = cs.network ?? {};
  // `mode: "blocked"` is nono's resolved form of `network.block` — an *inverted*
  // declaration: it claims un-reachability, so it is attested by egress being
  // absent under the profile while the baseline had it. Every other mode says how
  // egress is mediated, not whether any given destination is reachable; the
  // domains and ports below are the grants under it.
  if (n.mode === "blocked") {
    push("network.block", { category: "network", kind: "any", polarity: "absent", declares: EGRESS_FINDING, findingType: EGRESS_FINDING });
  } else if (n.mode) {
    push("network.mode", { category: "network", reason: NOT_MAPPED });
  }

  for (const d of n.allow_domains ?? []) {
    push(`network.allow_domains:${d}`, { category: "network", kind: "domain", domain: d, declares: EGRESS_FINDING, findingType: EGRESS_FINDING });
  }

  // An endpoint declares its host *and* a method/path rule on top. The host is a
  // declaration — egress to it is never a gap — but the probe only observes host
  // reachability, so the L7 half is unattested rather than quietly passed.
  for (const e of n.endpoints ?? []) {
    push(`network.endpoints:${e.host}`, {
      category: "network",
      kind: "domain",
      domain: e.host.replace(/:\d+$/, ""),
      declares: EGRESS_FINDING,
      reason: NO_FINDING,
    });
  }

  // `ports.localhost` (connect+bind) and `ports.listen` both resolve to ports the
  // child may hold open on localhost, which is exactly what the probe scans.
  for (const [where, ports] of Object.entries(n.ports ?? {})) {
    for (const port of Array.isArray(ports) ? ports : []) {
      push(`network.ports.${where}:${port}`, { category: "network", kind: "port", port, declares: PORT_FINDING, findingType: PORT_FINDING });
    }
  }

  // The secret's own source is the declaration the probe can check: an `env://`
  // credential says the run is handed that variable. Any other source says nothing
  // about the environment, so it stays unattested rather than reading as a failure.
  for (const c of cs.credentials ?? []) {
    const env = ENV_SOURCE.exec(c.source ?? "")?.[1];
    push(`credentials:${c.name}`, {
      category: "credentials",
      ...(env
        ? { kind: "env", env, declares: CRED_FINDING, findingType: CRED_FINDING }
        : { reason: NOT_FROM_ENV }),
    });
  }

  const p = cs.process ?? {};
  // Only `allow_all` declares other processes readable; `isolated` and
  // `allow_same_sandbox` both put the host's processes out of view, so they are
  // inverted declarations — attested by processes being *absent* under the profile
  // while the seeded baseline saw them, and a gap when they show up anyway.
  // ponytail: no per-process gap pass. The declaration is one mode over the whole
  // category, so every visible process would repeat the same verdict.
  if (p.process_info_mode) {
    push("process.process_info_mode", {
      category: "process",
      kind: "any",
      mode: p.process_info_mode,
      ...(p.process_info_mode === "allow_all" ? {} : { polarity: "absent" }),
      declares: PROCESS_FINDING,
      findingType: PROCESS_FINDING,
    });
  }
  if (p.signal_mode) push("process.signal_mode", { category: "process", reason: NO_FINDING });
  if (p.ipc_mode) push("process.ipc_mode", { category: "process", reason: NO_FINDING });
  if (p.allowed_commands?.length || p.blocked_commands?.length) {
    push("process.commands", { category: "process", reason: NO_FINDING });
  }

  for (const k of ["memory_bytes", "max_processes"]) {
    if (cs.resources?.[k] != null) push(`resources.${k}`, { category: "resources", reason: NO_FINDING });
  }

  // Environment filtering is the *whole* environment: `env_secret_detection` only
  // reports the secret-shaped subset, so it cannot say whether an allow/deny list
  // was applied. One unit for the policy, like command gating above.
  if (["allow_vars", "deny_vars", "set_vars"].some((k) => cs.environment?.[k])) {
    push("environment.filtering", { category: "environment", reason: NO_FINDING });
  }

  // Opt-in device/service gates. Nothing here opens a GPU device or asks
  // LaunchServices to open anything, so they are named rather than dropped.
  for (const k of ["allow_gpu", "allow_launch_services"]) {
    if (cs[k]) push(k, { category: "platform", reason: NO_FINDING });
  }

  return units;
}

/**
 * @param {object} input
 * @param {{id: string, version: string}} input.profile  declared profile identity
 * @param {object} input.capabilitySet  nono's resolved capability manifest
 * @param {object} input.sandbox  probe report from the run under the profile
 * @param {object} input.baseline  probe report from the seeded unconfined run
 * @param {string} [input.home]  home directory the reports were produced under
 */
export function attest({ profile, capabilitySet, sandbox, baseline, home }) {
  // A verdict that cannot be traced to an exact published claim is worthless.
  if (!profile?.id || !profile?.version) {
    throw new Error("attest: profile.id and profile.version are required — a verdict must name the claim it checked");
  }

  const units = declaredUnits(capabilitySet, home);
  const mediation = socketMediation(capabilitySet);

  const verdicts = units.map((u) => {
    if (!u.findingType) return { ...u, class: "unattested" };
    const underProfile = observed(sandbox, u.findingType).some((v) => covers(u, v));
    const inBaseline = observed(baseline, u.findingType).some((v) => covers(u, v));
    // An inverted declaration (a declared block) is delivered by *absence*: still
    // reachable means the sandbox is looser than its published claim, which is a
    // gap, the security-relevant direction.
    if (u.polarity === "absent") {
      if (underProfile) return { ...u, class: "gap" };
      return { ...u, class: inBaseline ? "match" : "unprovable" };
    }
    if (underProfile) return { ...u, class: "match" };
    // Declared, not observed — an overclaim only if the baseline could reach it.
    // Nothing there to reach in the first place is unprovable, not a failure.
    return { ...u, class: inBaseline ? "overclaim" : "unprovable" };
  });

  // Reachable with nothing declaring it: the security-relevant direction, kept in
  // its own list rather than pooled with the declared-side verdicts. An inverted
  // unit declares un-reachability, so it never suppresses a gap.
  const gaps = [];
  const gapTypes = [...Object.values(FS_FINDING), EGRESS_FINDING, CRED_FINDING];
  // Sockets only join the gap pass when mediation is on. Off, a reachable socket is
  // not a policy failure — it is listed below carrying the modifier instead.
  if (mediation === "pathname") gapTypes.push(SOCKET_FINDING);
  for (const findingType of gapTypes) {
    for (const value of observed(sandbox, findingType)) {
      const declared = units.some(
        (u) => u.declares === findingType && u.polarity !== "absent" && covers(u, value),
      );
      if (declared) continue;
      gaps.push({ class: "gap", findingType, ...(GAP_FIELD[findingType]?.(value) ?? { path: value }) });
    }
  }
  // ponytail: no gap pass over open ports. A port the profile never declared is
  // one the child did not open either — the probe scans localhost, so it sees the
  // host's own listeners, not the sandbox's. Add one if that stops holding.

  const attested = units.filter((u) => u.findingType).length;
  return {
    profile: { id: profile.id, version: profile.version, manifestVersion: capabilitySet.version },
    verdicts,
    gaps,
    // The reading modifiers, on the attestation itself so an unmediated socket surface
    // is visible without opening the profile.
    modifiers: { socketMediation: mediation },
    // What the attestation cannot see, stated on the attestation itself. Computed
    // after the verdicts and folded into nothing: a caveat qualifies the whole
    // reading, it does not change any single verdict or the coverage arithmetic.
    caveats:
      capabilitySet.process?.exec_strategy === "supervised"
        ? [{ id: ELEVATION, reason: ELEVATION_REASON }]
        : [],
    // Sockets observed while unmediated: reported, never as gaps.
    unmediated:
      mediation === "pathname"
        ? []
        : observed(sandbox, SOCKET_FINDING).map((path) => ({
            class: "unattested",
            findingType: SOCKET_FINDING,
            path,
            modifier: MEDIATION_OFF,
            reason: UNMEDIATED_REASON,
          })),
    excluded: UNDECLARABLE.filter((ft) => finding(sandbox, ft) !== undefined),
    coverage: {
      declared: units.length,
      attested,
      unattested: units.length - attested,
      attestedFraction: units.length ? attested / units.length : 0,
    },
  };
}
