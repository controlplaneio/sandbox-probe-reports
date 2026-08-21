// Table-driven over checked-in real-shaped documents: a resolved nono capability
// manifest and two probe reports. No nono binary, no network, no side effects.
// Run: node --test scripts/
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { attest, UNDECLARABLE, EXCLUDED_DECLARATIONS } from "./attest.mjs";

const load = (name) =>
  JSON.parse(readFileSync(new URL(`../tests/fixtures/attestation/${name}.json`, import.meta.url), "utf8"));

const PROFILE = { id: "nolabs-ai/codex", version: "0.4.1" };
const INPUT = {
  profile: PROFILE,
  capabilitySet: load("capability-set"),
  sandbox: load("report-under-profile"),
  baseline: load("report-baseline"),
  home: "/home/runner",
};
const result = attest(INPUT);
const byId = Object.fromEntries(result.verdicts.map((v) => [v.id, v.class]));

// One row per declared unit, one drift class each.
const EXPECTED = {
  // observed reachable under the profile (a directory grant covering the file seen)
  "filesystem.read:~/.ssh": "match",
  // not observed, but the baseline could reach it — the profile overclaims
  "filesystem.read:~/.aws/credentials": "overclaim",
  // not observed and not in the baseline either — nothing was there to reach
  "filesystem.read:~/.kube/config": "unprovable",
  // a readwrite grant is two declarations, and they can land differently
  "filesystem.read:/tmp/workspace": "unprovable",
  "filesystem.write:/tmp/workspace": "match",
  // reached under the profile
  "network.allow_domains:api.openai.com": "match",
  // not reached under the profile, but the baseline reached raw.githubusercontent.com
  // through the same suffix wildcard — the profile advertises what it does not deliver
  "network.allow_domains:.githubusercontent.com": "overclaim",
  // neither side reached it: nothing to prove either way
  "network.allow_domains:registry.npmjs.org": "unprovable",
  // declared open, observed open
  "network.ports.localhost:8080": "match",
  // declared, closed under the profile, open in the baseline
  "network.ports.listen:9229": "overclaim",
  // declared, nothing here observes the category
  "network.mode": "unattested",
  "network.endpoints:api.github.com:443": "unattested",
  // the secret the profile declares is in the run's own environment
  "credentials:openai": "match",
  // declared, absent under the profile, present in the baseline
  "credentials:github": "overclaim",
  // declared, and nothing handed it to the baseline either
  "credentials:anthropic": "unprovable",
  // process visibility is restricted, and no process is visible under the profile
  // while the seeded baseline saw one — the profile delivers what it declared
  "process.process_info_mode": "match",
  "process.signal_mode": "unattested",
  "process.ipc_mode": "unattested",
  "resources.max_processes": "unattested",
};

for (const [id, cls] of Object.entries(EXPECTED)) {
  test(`${id} -> ${cls}`, () => assert.equal(byId[id], cls));
}

test("every declared unit gets exactly one verdict and nothing else does", () => {
  assert.deepEqual(Object.keys(byId).sort(), Object.keys(EXPECTED).sort());
  assert.equal(result.verdicts.length, Object.keys(EXPECTED).length);
});

test("unattested is never folded into match and carries why", () => {
  for (const v of result.verdicts.filter((x) => x.class === "unattested")) {
    assert.ok(v.reason, `${v.id} must say why nothing observes it`);
  }
});

test("reachable-but-undeclared is a gap, kept distinct from the declared-side verdicts", () => {
  assert.deepEqual(result.gaps, [
    { class: "gap", findingType: "sensitive_readable_paths", path: "/etc/passwd" },
    { class: "gap", findingType: "writeable_paths", path: "/var/tmp" },
    // egress to a destination nothing declares; api.openai.com is declared as a
    // domain and api.github.com by an endpoint, so neither is a gap
    { class: "gap", findingType: "external_host_connectivity", host: "telemetry.example.net" },
    // a secret in the run's environment that no credential declares
    { class: "gap", findingType: "env_secret_detection", envKey: "NPM_TOKEN" },
  ]);
  assert.ok(!result.verdicts.some((v) => v.class === "gap"));
});

test("mount topology, hostname and user context are excluded, never gaps", () => {
  assert.deepEqual(result.excluded, [
    "mounted_volumes_detections",
    "hostname_detection",
    "user_context_detection",
  ]);
  for (const ft of UNDECLARABLE) {
    assert.ok(!result.gaps.some((g) => g.findingType === ft));
    assert.ok(!result.verdicts.some((v) => v.findingType === ft));
  }
});

test("coverage states the attested fraction of the declared surface", () => {
  assert.deepEqual(result.coverage, {
    declared: 19,
    attested: 14,
    unattested: 5,
    attestedFraction: 14 / 19,
  });
});

test("a profile's credentials are attested, not parked in the unattested list", () => {
  const creds = result.verdicts.filter((v) => v.category === "credentials");
  assert.equal(creds.length, 3);
  assert.ok(!creds.some((v) => v.class === "unattested"));
  // and the attested fraction rises by exactly the credentials that joined it
  const withoutCreds = attest({ ...INPUT, capabilitySet: { ...load("capability-set"), credentials: [] } });
  assert.ok(result.coverage.attestedFraction > withoutCreds.coverage.attestedFraction);
  assert.equal(result.coverage.attested, withoutCreds.coverage.attested + 3);
  assert.equal(result.coverage.unattested, withoutCreds.coverage.unattested);
});

test("a credential sourced from somewhere other than the environment stays unattested", () => {
  const cs = load("capability-set");
  cs.credentials = [{ name: "vault", source: "file:///run/secrets/token" }];
  const v = attest({ ...INPUT, capabilitySet: cs }).verdicts.find((x) => x.id === "credentials:vault");
  assert.equal(v.class, "unattested");
  assert.match(v.reason, /not sourced from the environment/);
});

test("coverage arithmetic counts network grants, so it moves when they do", () => {
  const cs = load("capability-set");
  cs.network.allow_domains = cs.network.allow_domains.slice(0, 1);
  cs.network.ports = { localhost: [8080] };
  const fewer = attest({ ...INPUT, capabilitySet: cs }).coverage;
  assert.deepEqual(fewer, { declared: 16, attested: 11, unattested: 5, attestedFraction: 11 / 16 });
  assert.notEqual(fewer.attestedFraction, result.coverage.attestedFraction);
});

// A declared block is the inverted case: it claims un-reachability, so it is
// attested by egress being *absent* under the profile while the baseline had it.
const blocked = (sandbox) =>
  attest({ ...INPUT, capabilitySet: load("capability-set-blocked"), sandbox });
const withoutEgress = (report) => ({
  ...report,
  findings: report.findings.filter((f) => f.findingType !== "external_host_connectivity"),
});

test("a declared network block the sandbox delivers is a match", () => {
  const r = blocked(withoutEgress(load("report-under-profile")));
  assert.equal(r.verdicts.find((v) => v.id === "network.block").class, "match");
  assert.ok(!r.gaps.some((g) => g.findingType === "external_host_connectivity"));
});

test("a declared network block with egress still observed is a gap", () => {
  const r = blocked(load("report-under-profile"));
  assert.equal(r.verdicts.find((v) => v.id === "network.block").class, "gap");
  // and every destination reached under it is undeclared, so it is a gap too
  assert.deepEqual(
    r.gaps.filter((g) => g.findingType === "external_host_connectivity").map((g) => g.host),
    ["api.openai.com", "api.github.com", "telemetry.example.net"],
  );
});

test("a declared network block is unprovable when the baseline had no egress either", () => {
  const r = attest({
    ...INPUT,
    capabilitySet: load("capability-set-blocked"),
    sandbox: withoutEgress(load("report-under-profile")),
    baseline: withoutEgress(load("report-baseline")),
  });
  assert.equal(r.verdicts.find((v) => v.id === "network.block").class, "unprovable");
});

// Process visibility. `isolated` and `allow_same_sandbox` both put the host's own
// processes out of view, so they are inverted declarations like a network block;
// only `allow_all` declares processes readable.
const withProcess = (report, ...findings) => ({ ...report, findings: [...report.findings, ...findings] });
const PROC = { findingType: "process_detection", task: "baseline_process_task", description: "Visible process", value: { pid: 4211, name: "sandbox-probe-decoy" } };
const PARENT = { findingType: "parent_process_detection", task: "baseline_process_task", description: "Parent process", value: { pid: 991, name: "bash" } };
const processVerdict = (over) => attest({ ...INPUT, ...over }).verdicts.find((v) => v.id === "process.process_info_mode");

test("restricted process visibility with a process visible anyway is a gap", () => {
  assert.equal(processVerdict({ sandbox: withProcess(load("report-under-profile"), PROC) }).class, "gap");
});

test("the run's own ancestry is not a visible process, so it does not break the match", () => {
  assert.equal(processVerdict({ sandbox: withProcess(load("report-under-profile"), PARENT) }).class, "match");
});

test("restricted process visibility is unprovable when the baseline saw no process either", () => {
  const baseline = { ...load("report-baseline"), findings: load("report-baseline").findings.filter((f) => f.findingType !== "process_detection") };
  assert.equal(processVerdict({ baseline }).class, "unprovable");
});

test("allow_all declares processes readable, so absence is an overclaim, not a match", () => {
  const cs = load("capability-set");
  cs.process.process_info_mode = "allow_all";
  assert.equal(processVerdict({ capabilitySet: cs }).class, "overclaim");
  cs.process.process_info_mode = "allow_same_sandbox";
  assert.equal(processVerdict({ capabilitySet: cs }).class, "match");
});

// Runtime capability elevation: a supervisor may grant access mid-run beyond the
// static declarations, so the scan may under-report reach. A caveat on the whole
// attestation — it qualifies the reading and changes nothing in it.
test("a profile enabling runtime capability elevation carries the caveat", () => {
  assert.deepEqual(result.caveats.map((c) => c.id), ["runtime-capability-elevation"]);
  assert.match(result.caveats[0].reason, /may under-report/);
});

test("the caveat changes no verdict, no gap and no coverage", () => {
  const cs = load("capability-set");
  cs.process.exec_strategy = "monitor";
  const without = attest({ ...INPUT, capabilitySet: cs });
  assert.deepEqual(without.caveats, []);
  assert.deepEqual(without.verdicts, result.verdicts);
  assert.deepEqual(without.gaps, result.gaps);
  assert.deepEqual(without.coverage, result.coverage);
});

test("the attestation names the profile and the manifest it checked", () => {
  assert.deepEqual(result.profile, { id: "nolabs-ai/codex", version: "0.4.1", manifestVersion: "0.1.0" });
});

test("a verdict that cannot name its claim is refused", () => {
  assert.throws(
    () => attest({ profile: { id: "nolabs-ai/codex" }, capabilitySet: load("capability-set"), sandbox: {}, baseline: {} }),
    /profile\.id and profile\.version are required/,
  );
});

// Every category nono declares that nothing here observes: named as unattested,
// never silently absent, and never counted as attested surface. The mapping and
// the reasons are in docs/attestation-mapping.md.
const unattestable = attest({ ...INPUT, capabilitySet: load("capability-set-unattestable") });
const UNATTESTABLE = [
  "process.signal_mode", // signal permission
  "process.ipc_mode", // IPC and semaphore mode
  "allow_gpu",
  "allow_launch_services",
  "resources.memory_bytes", // resource ceilings
  "resources.max_processes",
  "network.endpoints:api.github.com:443", // L7 method-and-path filtering
  "process.commands", // command execution gating
  "environment.filtering", // environment variable allow/deny filtering
  "network.mode", // how egress is mediated, not whether anything is reachable
];

for (const id of UNATTESTABLE) {
  test(`${id} is named unattested, with a reason`, () => {
    const v = unattestable.verdicts.find((x) => x.id === id);
    assert.equal(v?.class, "unattested", `${id} must be named, not silently absent`);
    assert.ok(v.reason, `${id} must say why nothing observes it`);
    assert.ok(!v.findingType, `${id} must not count as attested surface`);
  });
}

test("nothing in an unattestable profile passes as attested", () => {
  assert.deepEqual(unattestable.verdicts.map((v) => v.id).sort(), [...UNATTESTABLE].sort());
  assert.deepEqual(unattestable.coverage, {
    declared: UNATTESTABLE.length,
    attested: 0,
    unattested: UNATTESTABLE.length,
    attestedFraction: 0,
  });
});

test("hooks and supervisor-mediated URL opening are excluded by design, not unattested", () => {
  // They run outside the sandbox boundary, so naming them would advertise a probe
  // gap that cannot be closed. Declared in the fixture, absent from the verdicts.
  for (const id of Object.keys(EXCLUDED_DECLARATIONS)) {
    assert.ok(EXCLUDED_DECLARATIONS[id], `${id} must record why it is excluded`);
    assert.ok(!unattestable.verdicts.some((v) => v.id.startsWith(id)));
  }
});

// Socket grants, read against `linux.af_unix_mediation`. Mediation on: ordinary
// per-grant verdicts. Mediation off: the grants are not enforced at all, so every
// socket-derived result carries the modifier instead of reading as a policy failure.
const sockets = (fixture) => attest({ ...INPUT, capabilitySet: load(fixture) });
const mediated = sockets("capability-set-sockets");
const unmediated = sockets("capability-set-sockets-unmediated");
const socketGaps = (r) => r.gaps.filter((g) => g.findingType === "unix_socket_detection");

const SOCKET_EXPECTED = {
  // declared and observed under the profile
  "filesystem.unix_socket:/run/user/1000/bus": "match",
  // declared, and absent from the baseline too — nothing was there to reach
  "filesystem.unix_socket_bind:/run/user/1000/gpg-agent.sock": "unprovable",
  // a directory grant covers its direct children
  "filesystem.unix_socket_dir:/run/user/1000/nono": "match",
  // declared, not observed, but the baseline reached a socket in the subtree
  "filesystem.unix_socket_subtree_bind:/run/tmux-1000": "overclaim",
};

for (const [id, cls] of Object.entries(SOCKET_EXPECTED)) {
  test(`mediated ${id} -> ${cls}`, () =>
    assert.equal(mediated.verdicts.find((v) => v.id === id)?.class, cls));
}

test("a socket nothing declares is a gap, and a directory grant does not cover deeper paths", () => {
  assert.deepEqual(socketGaps(mediated), [
    // one level below the `_dir` grant, which is direct-children only
    { class: "gap", findingType: "unix_socket_detection", path: "/run/user/1000/nono/deep/nested.sock" },
    { class: "gap", findingType: "unix_socket_detection", path: "/run/docker.sock" },
  ]);
});

test("mediation off: no socket result is a gap or an overclaim", () => {
  assert.deepEqual(socketGaps(unmediated), []);
  const socketVerdicts = unmediated.verdicts.filter((v) => v.declares === "unix_socket_detection");
  assert.equal(socketVerdicts.length, Object.keys(SOCKET_EXPECTED).length);
  for (const v of socketVerdicts) {
    assert.equal(v.class, "unattested");
    assert.equal(v.modifier, "socket-mediation-disabled");
    assert.match(v.reason, /af_unix_mediation is off/);
  }
});

test("mediation off: sockets observed anyway are reported carrying the modifier", () => {
  assert.deepEqual(
    unmediated.unmediated.map((u) => [u.path, u.class, u.modifier]),
    [
      ["/run/user/1000/bus", "unattested", "socket-mediation-disabled"],
      ["/run/user/1000/nono/agent.sock", "unattested", "socket-mediation-disabled"],
      ["/run/user/1000/nono/deep/nested.sock", "unattested", "socket-mediation-disabled"],
      ["/run/docker.sock", "unattested", "socket-mediation-disabled"],
    ],
  );
  assert.deepEqual(mediated.unmediated, []);
});

test("the modifier is on the attestation, so the profile need not be opened to see it", () => {
  assert.deepEqual(unmediated.modifiers, { socketMediation: "off" });
  assert.deepEqual(mediated.modifiers, { socketMediation: "pathname" });
  // absent means off: mediation is opt-in
  assert.deepEqual(result.modifiers, { socketMediation: "off" });
});

test("unenforced socket grants count as declared-but-unattested, lowering coverage", () => {
  assert.deepEqual(unmediated.coverage, { declared: 4, attested: 0, unattested: 4, attestedFraction: 0 });
  assert.deepEqual(mediated.coverage, { declared: 4, attested: 4, unattested: 0, attestedFraction: 1 });
});
