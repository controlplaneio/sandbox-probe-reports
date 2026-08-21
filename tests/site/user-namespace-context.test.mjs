// Ticket #38: the probe now emits `user-namespace` as a kernel-attested mechanism
// beside the inferred wrapper name (both as sandbox_detection findings). It must
// render as a context signal — never a capability category, never the uncounted
// "other" column — and must not move any exposure count.
// Run: node tests/site/user-namespace-context.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

// app.js is a plain <script> with a self-invoking boot(); strip from boot onward
// and export the pure functions. Same approach as named-pipe-category.test.mjs.
const pure = appJs.split("// ── boot")[0];
const loader = new Function(
  "module",
  "document",
  "getComputedStyle",
  `${pure}\nmodule.exports = { FT2CAT, CATEGORIES, MECHANISMS, leakedCats, cellStates, sandboxOf, mechanismsOf, build };`
);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { FT2CAT, MECHANISMS, leakedCats, cellStates, sandboxOf, mechanismsOf, build } = mod.exports;

const sd = (v) => ({ findingType: "sandbox_detection", task: "baseline_sandbox_detector", value: v });
const report = (harness, findings) => ({
  os: "linux", harness, runTimestamp: "2026-07-31T08:00:00Z",
  report: { findings, metadata: { tags: ["os=linux", `harness=${harness}`] }, probeBinary: { commit: "c" } },
});

// -- user-namespace is a mechanism, not a wrapper name and not a category --
assert.ok(MECHANISMS.has("user-namespace"));
assert.equal(FT2CAT.user_namespace, undefined);

// A corrected bwrap run: wrapper name resolves, mechanisms sit beside it.
const corrected = report("claude-sandbox", [
  sd("bubblewrap"), sd("user-namespace"), sd("seccomp-filter"), sd("no-new-privs"),
  { findingType: "user_context_detection", value: { euid: 1001 } },
  { findingType: "sensitive_readable_paths", value: [] },
]);
assert.equal(sandboxOf(corrected), "bubblewrap");
assert.deepEqual(mechanismsOf(corrected), ["user-namespace", "seccomp-filter", "no-new-privs"]);

// -- context signal: never lands in the uncounted "other" column --
assert.ok(!leakedCats(corrected).has("other"), "user-namespace must not leak into other");

// -- exposure is unchanged by the mechanism appearing --
const baseline = report("direct", [
  { findingType: "sensitive_readable_paths", value: ["/home/u/.aws/credentials"] },
  { findingType: "user_context_detection", value: { euid: 1001 } },
]);
const before = report("claude-sandbox", corrected.report.findings.filter((f) => f.value !== "user-namespace"));
assert.deepEqual(cellStates(corrected, baseline), cellStates(before, baseline));

const exposure = (row) => build([baseline, row])[`linux/${row.harness}`].at(-1).exposure;
assert.equal(exposure(corrected), exposure(before));
assert.ok(exposure(corrected) <= 8);

// -- a run whose wrapper could not be named still reports the proven mechanism --
const mechOnly = report("srt", [sd("user-namespace"), sd("no-new-privs")]);
assert.equal(sandboxOf(mechOnly), "none");
assert.deepEqual(mechanismsOf(mechOnly), ["user-namespace", "no-new-privs"]);

console.log("ok - user-namespace renders as a context signal and moves no exposure count");
