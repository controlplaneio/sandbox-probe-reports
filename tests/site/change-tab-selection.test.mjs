// Pins what a selected tab shows: an identity tab shows that identity's changes
// and nothing else, the All tab shows everything, and both are UNCAPPED — the
// expanded view exists precisely to carry hundreds of findings that the 25-item
// list on the page cannot.
// Run: node --test tests/site/change-tab-selection.test.mjs
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
  `${pure}\nmodule.exports = { changesForTab, ALL_TAB, ALL_CHANGES_CAP };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { changesForTab, ALL_TAB, ALL_CHANGES_CAP } = mod.exports;

const change = (id, n) => ({
  id, ts: `2026-01-${String(n).padStart(2, "0")}T00:00:00Z`,
  cat: "FS read", from: "blocked", to: "leaked", cause: "no config change", degraded: true,
});

// 300 changes split across three identities, interleaved and oldest first.
const IDS = ["linux/claude", "linux/gemini", "darwin/claude"];
const many = Array.from({ length: 300 }, (_, i) => change(IDS[i % 3], (i % 28) + 1));

test("an identity tab returns only that identity's changes", () => {
  const got = changesForTab(many, "linux/gemini");
  assert.equal(got.length, 100, "one of three interleaved identities owns 100 of the 300 changes");
  assert.ok(got.length > 0, "the filter must not return an empty list");
  assert.deepEqual([...new Set(got.map((c) => c.id))], ["linux/gemini"],
    "an identity tab must contain no other identity's changes");
});

test("an identity tab is uncapped", () => {
  const got = changesForTab(many, "linux/claude");
  assert.ok(got.length > ALL_CHANGES_CAP,
    `the expanded view must exceed the ${ALL_CHANGES_CAP}-item page cap (got ${got.length})`);
  assert.equal(got.length, 100, "every change for that identity must be present");
});

test("the All tab returns every change, uncapped", () => {
  const got = changesForTab(many, ALL_TAB);
  assert.equal(got.length, 300, "the All tab must return all 300 changes");
  assert.deepEqual([...new Set(got.map((c) => c.id))].sort(), [...IDS].sort(),
    "the All tab must span every identity");
});

test("a selected tab is newest first", () => {
  const tss = changesForTab(many, ALL_TAB).map((c) => c.ts);
  assert.deepEqual(tss, [...tss].sort().reverse(), "the expanded view must be ordered newest first");
});

test("a tab with no matching changes is empty, not everything", () => {
  assert.deepEqual(changesForTab(many, "windows/nothing"), [],
    "an identity with no changes must not fall back to showing all identities");
});
