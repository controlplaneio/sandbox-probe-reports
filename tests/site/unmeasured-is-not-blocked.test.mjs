// A finding that is ABSENT means the task did not run. A finding that is EMPTY means the
// task ran and found nothing. Conflating them made a failed scan render as a security
// improvement, which put five flips in the CHANGES panel that never happened.
//
// The corpus that exposed it: across 165 published reports tcp_ports_open appeared
// non-empty 130 times, absent 35 times, and empty exactly 0 times — so "Local svc blocked"
// was never once a measured negative. Meanwhile writeable_paths had 83 empties, because
// that task does emit [] when it finds nothing.
//
// Run: node tests/site/unmeasured-is-not-blocked.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

// same loader shape as the other site tests: pure half of app.js, no DOM/fetch.
const pure = appJs.split("// ── boot")[0];
const loader = new Function("module", "document", "getComputedStyle", `${pure}\nmodule.exports = { build, flips, cellStates };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { build, flips, cellStates } = mod.exports;

const tcp = (v) => ({ findingType: "tcp_ports_open", value: v });
const reads = (v) => ({ findingType: "sensitive_readable_paths", value: v });
const row = (harness, ts, findings, version = "1.0") => ({
  os: "linux", harness, runTimestamp: ts,
  report: { findings, metadata: { tags: [`${harness}=${version}`] }, probeBinary: { binaryVersion: "v6.2.1" } },
});

const T1 = "2026-01-01T00:00:00Z", T2 = "2026-02-01T00:00:00Z", T3 = "2026-03-01T00:00:00Z";

// -- absent is unprovable; empty is a real measured negative --
{
  const base = row("direct", T1, [tcp([22]), reads(["/etc/passwd"])]);
  const scanRan = cellStates(row("h", T1, [tcp([]), reads([])]), base);
  const scanMissing = cellStates(row("h", T1, [reads([])]), base);

  assert.equal(scanRan.local_services, "blocked",
    "an empty port list is a scan that ran and found nothing — a real negative");
  assert.equal(scanMissing.local_services, "unprovable",
    "an absent port finding is a scan that did not run — it proves nothing");
  assert.equal(scanMissing.fs_read, "blocked",
    "categories the row did measure are unaffected");
}

// -- a baseline that did not measure the category cannot establish achievability --
{
  const baseNoScan = row("direct", T1, [reads(["/etc/passwd"])]);
  const states = cellStates(row("h", T1, [tcp([])]), baseNoScan);
  assert.equal(states.local_services, "unprovable",
    "with no baseline measurement there is nothing to normalise against");
}

// -- euid is a measurement too: absent user context is not proof of non-root --
{
  const base = row("direct", T1, [reads(["/etc/passwd"])]);
  const noCtx = cellStates(row("h", T1, [reads([])]), base);
  assert.equal(noCtx.privileged, "unprovable",
    "a missing user_context_detection must not read as 'not root'");
}

// -- THE REGRESSION GUARD: a dropped scan must not manufacture a flip pair.
//    This is the macos/cline shape exactly — leaked, then the scan goes missing,
//    then leaked again — which the panel rendered as an improvement followed by
//    a regression, attributed to two harness version bumps that were coincidental.
{
  const rows = [
    row("direct", T1, [tcp([22])]), row("direct", T2, [tcp([22])]), row("direct", T3, [tcp([22])]),
    row("cline", T1, [tcp([22])], "3.0.52"),
    row("cline", T2, [], "3.0.55"),            // scan dropped: no finding at all
    row("cline", T3, [tcp([22])], "3.0.56"),
  ];
  const model = build(rows);
  const series = model["linux/cline"].map((p) => p.states.local_services);
  assert.deepEqual(series, ["leaked", "unprovable", "leaked"],
    "the dropped scan sits between two leaks as unprovable, not as a block");

  const f = flips(model).filter((x) => x.id === "linux/cline");
  assert.deepEqual(f, [], "a dropped scan must produce no flip in either direction");
}

// -- a genuine regression still surfaces: measured blocked, then measured leaked --
{
  const rows = [
    row("direct", T1, [tcp([22])]), row("direct", T2, [tcp([22])]),
    row("sbx", T1, [tcp([])], "1.0"),          // measured: nothing reachable
    row("sbx", T2, [tcp([22])], "1.1"),        // measured: reachable
  ];
  const f = flips(build(rows)).filter((x) => x.id === "linux/sbx");
  assert.equal(f.length, 1, "a real blocked->leaked transition must still be reported");
  assert.equal(f[0].from, "blocked");
  assert.equal(f[0].to, "leaked");
  assert.ok(f[0].degraded, "and must be marked as a regression");
}

// -- two runs sharing a fingerprint are two points, not one.
//    The collapse kept the latest and discarded the rest, which threw away the
//    disagreements that prove a measurement unstable: macos/claude-sandbox observed
//    tcp [49173] at 12:58 on 2026-08-21 and the 13:06 run overwrote it silently. --
{
  const sameDayA = "2026-04-01T12:58:00Z", sameDayB = "2026-04-01T13:06:00Z";
  const rows = [
    row("direct", sameDayA, [tcp([22])]), row("direct", sameDayB, [tcp([22])]),
    row("sbx", sameDayA, [tcp([49173])], "1.0"),
    row("sbx", sameDayB, [tcp([])], "1.0"),    // identical fingerprint, different result
  ];
  const pts = build(rows)["linux/sbx"];
  assert.equal(pts.length, 2, "a same-fingerprint re-run must not be collapsed away");
  assert.deepEqual(pts.map((p) => p.states.local_services), ["leaked", "blocked"]);

  const f = flips(build(rows)).filter((x) => x.id === "linux/sbx");
  assert.equal(f.length, 1, "two runs that disagree are a finding, not a duplicate");
  assert.equal(f[0].cause, "no config change",
    "and nothing changed between them, which is the truthful attribution");
}

console.log("ok - absent is unmeasured, empty is a measured negative, and re-runs are not collapsed");
