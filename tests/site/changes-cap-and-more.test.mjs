// Pins the bottom "Changes" section at 25 items, and pins the "more" affordance
// to the boundary: it appears only when the data actually exceeds the cap, so a
// page with 25 changes shows no misleading "more" and a page with 26 does.
// Run: node --test tests/site/changes-cap-and-more.test.mjs
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
  `${pure}\nmodule.exports = { cappedChanges, needsMore, ALL_CHANGES_CAP };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { cappedChanges, needsMore, ALL_CHANGES_CAP } = mod.exports;

const change = (n) => ({
  id: `linux/h${n % 3}`, ts: `2026-01-${String(n).padStart(2, "0")}T00:00:00Z`,
  cat: "FS read", from: "blocked", to: "leaked", cause: "no config change", degraded: true,
});
const oldestFirst = (n) => Array.from({ length: n }, (_, i) => change(i + 1));

test("the bottom section caps at 25", () => {
  assert.equal(ALL_CHANGES_CAP, 25, "the documented bottom-section cap is 25");
  const got = cappedChanges(oldestFirst(80));
  assert.equal(got.length, 25, "the bottom section must render exactly 25 of 80 changes");
  assert.equal(got[0].ts, "2026-01-80T00:00:00Z", "the bottom section must also lead with the newest");
});

test("fewer than the cap renders every change", () => {
  assert.equal(cappedChanges(oldestFirst(4)).length, 4, "4 changes must render as 4 items");
});

test("exactly 25 changes needs no more affordance", () => {
  const fl = oldestFirst(25);
  assert.equal(cappedChanges(fl).length, 25, "all 25 are already on the page");
  assert.equal(needsMore(fl), false, "25 changes are fully shown, so there is nothing more to open");
});

test("26 changes needs the more affordance", () => {
  const fl = oldestFirst(26);
  assert.equal(cappedChanges(fl).length, 25, "only 25 of 26 fit the capped list");
  assert.equal(needsMore(fl), true, "26 changes exceed the cap, so more must be offered");
});

test("no changes needs no more affordance", () => {
  assert.equal(needsMore([]), false, "an empty change list must not offer more");
});
