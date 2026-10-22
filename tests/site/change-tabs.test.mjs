// Pins the tab list of the expanded changes view: tabs are derived from the data
// (never a hardcoded harness list, so a new identity gets a tab with no code
// change and a departed one loses it), "All" leads, unconfined `/direct`
// baselines are excluded the same way flips() excludes them, and the order does
// not depend on the order the changes happen to arrive in.
// Run: node --test tests/site/change-tabs.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

// same loader shape as the other site tests: pure half of app.js, no DOM/fetch.
const pure = appJs.split("// ── boot")[0];
const loader = new Function("module", "document", "getComputedStyle",
  `${pure}\nmodule.exports = { changeTabs, ALL_TAB };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { changeTabs, ALL_TAB } = mod.exports;

const change = (id, ts) => ({
  id, ts, cat: "FS read", from: "blocked", to: "leaked",
  cause: "no config change", degraded: true,
});

const fl = [
  change("linux/gemini", "2026-01-04T00:00:00Z"),
  change("darwin/claude", "2026-01-03T00:00:00Z"),
  change("linux/claude", "2026-01-02T00:00:00Z"),
  change("linux/claude", "2026-01-01T00:00:00Z"),
];

test("tabs are derived from the identities present in the data", () => {
  assert.deepEqual(changeTabs(fl),
    [ALL_TAB, "darwin/claude", "linux/claude", "linux/gemini"],
    "every non-baseline identity in the data gets exactly one tab, All first");
});

test("All is always the first tab", () => {
  assert.equal(changeTabs(fl)[0], ALL_TAB, "the All tab must lead the tablist");
  assert.equal(changeTabs([])[0], ALL_TAB, "All is present even with no changes");
  assert.equal(changeTabs([]).length, 1, "with no changes there are no identity tabs");
});

test("an identity appearing many times still gets one tab", () => {
  const tabs = changeTabs(fl);
  assert.equal(tabs.filter((t) => t === "linux/claude").length, 1,
    "linux/claude has two changes but must get one tab");
});

test("unconfined /direct baselines never get a tab", () => {
  const withBaseline = [...fl, change("linux/direct", "2026-01-05T00:00:00Z")];
  const tabs = changeTabs(withBaseline);
  assert.ok(!tabs.includes("linux/direct"), "a /direct baseline is not a sandbox and must not get a tab");
  assert.deepEqual(tabs, changeTabs(fl), "excluding the baseline must leave the rest of the tablist intact");
});

test("tab order does not depend on the arrival order of the changes", () => {
  const shuffled = [fl[2], fl[0], fl[3], fl[1]];
  assert.deepEqual(changeTabs(shuffled), changeTabs(fl),
    "the tablist must be stable-sorted, not first-seen order");
});

test("a new identity joins the tablist with no code change", () => {
  const tabs = changeTabs([...fl, change("windows/codex", "2026-01-06T00:00:00Z")]);
  assert.ok(tabs.includes("windows/codex"), "an identity never seen before must get its own tab");
  assert.equal(tabs.length, 5, "All plus four identities");
});
