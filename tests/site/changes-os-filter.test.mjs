// Pins the OS filter on the two changes sections: the option list is derived
// from the loaded reports (never hardcoded, the same reasoning as the matrix
// columns and the change tabs), the OS is read back out of the identity key, and
// every cap is applied AFTER the filter — including the N in the
// "Show all N changes" button and its appear/hide threshold. Capping first and
// filtering second shows fewer items than the cap while looking entirely
// correct, which is the one failure here nobody would notice.
// Run: node --test tests/site/changes-os-filter.test.mjs
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
  `${pure}\nmodule.exports = { osOptions, osOfChange, changesInSel, latestChangesForSel,
     cappedChangesForSel, needsMoreForSel, changeCountForSel, noChangesNote,
     OS_ALL, HARNESS_ALL, LATEST_CHANGES_CAP, ALL_CHANGES_CAP };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const {
  osOptions, osOfChange, changesInSel, latestChangesForSel, cappedChangesForSel,
  needsMoreForSel, changeCountForSel, noChangesNote: noteForSel, OS_ALL, HARNESS_ALL,
  LATEST_CHANGES_CAP, ALL_CHANGES_CAP,
} = mod.exports;

// The section helpers were widened to take a {os, harness} selection when the
// harness filter landed beside the OS one (see changes-harness-filter.test.mjs).
// These shims pin the OS-only behaviour this file was written to pin: every
// assertion below is unchanged in intent, and now also proves the OS half still
// behaves with the harness left unset.
const onlyOs = (os) => ({ os, harness: HARNESS_ALL });
const changesInOs = (fl, os) => changesInSel(fl, onlyOs(os));
const latestChangesForOs = (fl, os) => latestChangesForSel(fl, onlyOs(os));
const cappedChangesForOs = (fl, os) => cappedChangesForSel(fl, onlyOs(os));
const needsMoreForOs = (fl, os) => needsMoreForSel(fl, onlyOs(os));
const changeCountForOs = (fl, os) => changeCountForSel(fl, onlyOs(os));
const noChangesNote = (os) => noteForSel(onlyOs(os));

// n synthetic changes for one identity, oldest first, dated from `day`, so a
// helper that slices an unsorted array cannot pass by accident.
const change = (id, day) => ({
  id, ts: `2026-01-${String(day).padStart(2, "0")}T00:00:00Z`,
  cat: "FS read", from: "blocked", to: "leaked", cause: "no config change", degraded: true,
});
const run = (id, from, n) => Array.from({ length: n }, (_, i) => change(id, from + i));

// The shape that separates "cap then filter" from "filter then cap": the OS
// under test is entirely OLDER than the noise, so the unfiltered newest N
// contains none of it.
const windowsOldLinuxNew = (nWin, nLin) =>
  [...run("windows/copilot", 1, nWin), ...run("linux/claude", 1 + nWin, nLin)];

test("the OS option list is derived from the report data, never hardcoded", () => {
  const rows = [
    { os: "linux" }, { os: "darwin" }, { os: "windows" },
    { os: "freebsd" }, { os: "linux" }, { os: "windows" },
  ];
  assert.deepEqual(osOptions(rows), ["darwin", "freebsd", "linux", "windows"],
    "every OS present in the data gets exactly one option, sorted, none excluded");
});

test("the OS option list does not depend on the arrival order of the reports", () => {
  const a = [{ os: "windows" }, { os: "linux" }, { os: "darwin" }];
  const b = [{ os: "darwin" }, { os: "windows" }, { os: "linux" }];
  assert.deepEqual(osOptions(a), osOptions(b),
    "the option list must be sorted, not first-seen order");
});

test("the OS of a change is read out of its identity key", () => {
  assert.equal(osOfChange(change("windows/copilot", 1)), "windows");
  assert.equal(osOfChange(change("darwin/codex", 1)), "darwin");
  assert.equal(osOfChange(change("linux/claude", 1)), "linux");
});

test("filtering to one OS returns only that OS's changes", () => {
  const fl = [...run("linux/claude", 1, 3), ...run("darwin/codex", 4, 2), ...run("windows/copilot", 6, 4)];
  const got = changesInOs(fl, "windows");
  assert.equal(got.length, 4, "only the four windows changes survive the filter");
  assert.ok(got.every((f) => f.id.startsWith("windows/")),
    "no change from another OS may appear under a windows filter");
});

test("the all sentinel returns every change", () => {
  const fl = [...run("linux/claude", 1, 3), ...run("windows/copilot", 4, 4)];
  assert.equal(changesInOs(fl, OS_ALL).length, 7, "the all option must exclude nothing");
});

test("an OS prefix is matched exactly, not as a substring", () => {
  const fl = run("linux-arm/claude", 1, 2);
  assert.deepEqual(changesInOs(fl, "linux"), [],
    "linux must not swallow a linux-arm identity");
});

test("the top cap is applied after the filter, not before", () => {
  // 12 windows changes, all older than 30 linux ones: the unfiltered newest 10
  // are pure linux, so a cap-then-filter implementation returns zero.
  const fl = windowsOldLinuxNew(12, 30);
  const got = latestChangesForOs(fl, "windows");
  assert.equal(got.length, LATEST_CHANGES_CAP,
    "the top section must show 10 of the 12 filtered changes, not 10 of the unfiltered set filtered down");
  assert.ok(got.every((f) => f.id.startsWith("windows/")),
    "every item shown under a windows filter must be a windows change");
  assert.equal(got[0].ts, "2026-01-12T00:00:00Z",
    "the filtered set is still ordered newest first");
});

test("the bottom cap is applied after the filter, not before", () => {
  // 30 windows changes, all older than 40 linux ones.
  const fl = windowsOldLinuxNew(30, 40);
  const got = cappedChangesForOs(fl, "windows");
  assert.equal(got.length, ALL_CHANGES_CAP,
    "the bottom section must show 25 of the 30 filtered changes, not 25 of the unfiltered set filtered down");
  assert.ok(got.every((f) => f.id.startsWith("windows/")),
    "every item in the capped bottom list must come from the active filter");
  assert.equal(got[0].ts, "2026-01-30T00:00:00Z", "newest filtered change leads");
});

test("the top section under a filter shows what exists when it is under the cap", () => {
  const fl = windowsOldLinuxNew(3, 40);
  const got = latestChangesForOs(fl, "windows");
  assert.equal(got.length, 3, "3 windows changes must render as 3 items, not padded and not emptied");
});

test("needsMore is computed on the filtered set — 25 inside the filter offers nothing more", () => {
  const fl = windowsOldLinuxNew(25, 100);
  assert.equal(needsMoreForOs(fl, "windows"), false,
    "all 25 windows changes are already on the page, so there is nothing more to open");
  assert.equal(needsMoreForOs(fl, OS_ALL), true,
    "unfiltered, the same data does exceed the cap");
});

test("needsMore is computed on the filtered set — 26 inside the filter offers more", () => {
  const fl = windowsOldLinuxNew(26, 100);
  assert.equal(needsMoreForOs(fl, "windows"), true,
    "26 windows changes exceed the cap, so the expanded view must be offered");
});

test("the N in the button counts the filtered set, not the whole history", () => {
  const fl = windowsOldLinuxNew(26, 100);
  assert.equal(changeCountForOs(fl, "windows"), 26,
    "the button must offer the 26 changes the filter admits, not all 126");
  assert.equal(changeCountForOs(fl, OS_ALL), 126, "unfiltered, N is the whole history");
});

test("an OS with no changes offers no more affordance and no items", () => {
  const fl = run("linux/claude", 1, 40);
  assert.deepEqual(latestChangesForOs(fl, "darwin"), [], "no darwin changes means no items");
  assert.equal(needsMoreForOs(fl, "darwin"), false, "an empty filtered list must not offer more");
  assert.equal(changeCountForOs(fl, "darwin"), 0, "and N must be zero");
});

test("the empty state says the filter caused it, not that there is no history", () => {
  const note = noChangesNote("windows");
  assert.match(note, /windows/, "the note must name the OS that is being filtered to");
  assert.match(note, /filter/i, "the note must attribute the emptiness to the filter");
  assert.equal(noChangesNote(OS_ALL), "No flips yet.",
    "unfiltered, the existing empty state wording is unchanged");
});

test("filtering does not mutate the change list it is given", () => {
  const fl = windowsOldLinuxNew(4, 4);
  const before = fl.map((f) => f.ts);
  cappedChangesForOs(fl, "windows");
  latestChangesForOs(fl, OS_ALL);
  assert.deepEqual(fl.map((f) => f.ts), before,
    "the three views share one list, so none of them may reorder or splice it");
});
