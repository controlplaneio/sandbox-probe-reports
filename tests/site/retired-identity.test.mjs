// Ticket #30: an identity whose most recent run predates the latest scan is
// retired — no matrix row, no exposure line ending mid-axis — while a
// first-time identity joins with no code change and everyone else is
// untouched. Run: node tests/site/retired-identity.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

// same loader shape as the other site tests: pure half of app.js, no DOM/fetch.
const pure = appJs.split("// ── boot")[0];
const loader = new Function("module", "document", "getComputedStyle", `${pure}\nmodule.exports = { build };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { build } = mod.exports;

const readable = [{ findingType: "sensitive_readable_paths", value: ["/etc/passwd"] }];
const blocked = [{ findingType: "sensitive_readable_paths", value: [] }];
const row = (harness, ts, findings, commit = ts) => ({
  os: "linux", harness, runTimestamp: ts,
  report: { findings, metadata: { tags: [`${harness}=1.0`] }, probeBinary: { commit } },
});

const OLD = "2026-01-01T00:00:00Z", NEW = "2026-02-01T00:00:00Z", NEXT = "2026-03-01T00:00:00Z";
const rows = [
  row("direct", OLD, readable), row("direct", NEW, readable),
  row("staying", OLD, readable), row("staying", NEW, blocked),
  row("gvisor", OLD, blocked),          // retired: last run predates the latest scan
  row("newcomer", NEW, readable),       // first appearance, latest scan only
];

const model = build(rows);

// -- acceptance: the retired identity is gone from the model the matrix and
//    the exposure chart both render from --
assert.ok(!("linux/gvisor" in model), "retired identity must not appear in the model");

// -- acceptance: arrival still works with no code change --
assert.ok("linux/newcomer" in model, "a first-time identity must join");
assert.equal(model["linux/newcomer"].length, 1);

// -- acceptance: remaining identities' points, cell states and exposure are
//    unchanged by the retirement --
const staying = model["linux/staying"];
assert.equal(staying.length, 2);
assert.deepEqual(staying.map((p) => p.ts), [OLD, NEW]);
assert.equal(staying[0].states.fs_read, "leaked");
assert.equal(staying[1].states.fs_read, "blocked");
assert.deepEqual(staying.map((p) => p.exposure), [1, 0]);
assert.ok("linux/direct" in model, "the baseline row stays");

// -- a re-run carrying the same fingerprint as an earlier one (same probe
//    version, same harness version) is now its own point rather than being
//    collapsed onto the earlier one, so retirement reads a real run timestamp
//    either way --
const reRun = build([
  ...rows,
  row("direct", NEXT, readable),
  row("staying", NEXT, blocked, NEW),   // same fingerprint as the NEW point
]);
assert.ok("linux/staying" in reRun, "a re-run at an existing fingerprint must not read as retired");
assert.equal(reRun["linux/staying"].length, 3, "a same-fingerprint re-run is its own point, not a merge");
assert.ok(!("linux/newcomer" in reRun), "an identity that stops receiving runs retires");

console.log("ok - retired identities leave the matrix and charts; arrivals still join");
