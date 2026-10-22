// Pins the "Latest changes" section at the top of the page: it shows the 10 most
// recent changes and no more, newest first, and degrades to whatever exists when
// there are fewer than 10 — it must never become "all changes, rendered twice".
// Run: node --test tests/site/latest-changes-cap.test.mjs
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
  `${pure}\nmodule.exports = { latestChanges, LATEST_CHANGES_CAP };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { latestChanges, LATEST_CHANGES_CAP } = mod.exports;

// n synthetic changes, oldest first, so a function that merely slices an
// unsorted array cannot pass by accident.
const change = (n) => ({
  id: `linux/h${n % 3}`, ts: `2026-01-${String(n).padStart(2, "0")}T00:00:00Z`,
  cat: "FS read", from: "blocked", to: "leaked", cause: "no config change", degraded: true,
});
const oldestFirst = (n) => Array.from({ length: n }, (_, i) => change(i + 1));

test("the top section caps at 10 even when there are far more changes", () => {
  assert.equal(LATEST_CHANGES_CAP, 10, "the documented top-section cap is 10");
  const got = latestChanges(oldestFirst(40));
  assert.equal(got.length, 10, "the top section must render exactly 10 of 40 changes");
});

test("the top section is newest first", () => {
  const got = latestChanges(oldestFirst(40));
  assert.equal(got[0].ts, "2026-01-40T00:00:00Z", "the first item must be the newest change");
  assert.equal(got.at(-1).ts, "2026-01-31T00:00:00Z", "the tenth item must be the tenth-newest change");
  const tss = got.map((c) => c.ts);
  assert.deepEqual(tss, [...tss].sort().reverse(), "the top section must be ordered newest first");
});

test("fewer than 10 changes shows what exists, not a padded or empty list", () => {
  const got = latestChanges(oldestFirst(3));
  assert.equal(got.length, 3, "3 changes must render as 3 items");
  assert.equal(got[0].ts, "2026-01-03T00:00:00Z", "even a short list must lead with the newest");
});

test("exactly 10 changes shows all 10", () => {
  assert.equal(latestChanges(oldestFirst(10)).length, 10, "10 changes must render as 10 items");
});

test("no changes yields an empty list for the muted empty state", () => {
  assert.deepEqual(latestChanges([]), [], "no changes must yield no items");
});
