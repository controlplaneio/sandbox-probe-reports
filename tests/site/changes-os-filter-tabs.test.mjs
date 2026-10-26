// Pins the bottom OS filter's reach into the tabbed view — tabs, their counts
// and the listed changes all respect it, and an identity the filter excludes
// loses its tab rather than keeping an empty one — and pins the two section
// filters as independent values. A single page-wide "current OS" would let
// someone scanning "what changed on Windows lately" at the top silently
// re-scope the bottom section, which is the failure this is designed against.
// Run: node --test tests/site/changes-os-filter-tabs.test.mjs
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
  `${pure}\nmodule.exports = { changeTabsForSel, changesForTabInSel, newChangeFilters, setChangeFilter,
     latestChangesForSel, cappedChangesForSel, changeCountForSel, ALL_TAB, OS_ALL, HARNESS_ALL };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const {
  changeTabsForSel, changesForTabInSel, newChangeFilters, setChangeFilter,
  latestChangesForSel, cappedChangesForSel, changeCountForSel, ALL_TAB, OS_ALL, HARNESS_ALL,
} = mod.exports;

// The section helpers and the filter holder were widened to a {os, harness}
// selection when the harness filter landed beside the OS one (see
// changes-harness-filter.test.mjs). These shims pin the OS-only behaviour this
// file was written to pin: every assertion below is unchanged in intent, and the
// state ones now read each section's `.os` out of the real holder.
const onlyOs = (os) => ({ os, harness: HARNESS_ALL });
const changeTabsForOs = (fl, os) => changeTabsForSel(fl, onlyOs(os));
const changesForTabInOs = (fl, os, tab) => changesForTabInSel(fl, onlyOs(os), tab);
const latestChangesForOs = (fl, os) => latestChangesForSel(fl, onlyOs(os));
const cappedChangesForOs = (fl, os) => cappedChangesForSel(fl, onlyOs(os));
const changeCountForOs = (fl, os) => changeCountForSel(fl, onlyOs(os));
const newOsFilters = newChangeFilters;
const setOsFilter = (filters, section, os) => setChangeFilter(filters, section, { os }, []);

const change = (id, day) => ({
  id, ts: `2026-01-${String(day).padStart(2, "0")}T00:00:00Z`,
  cat: "FS read", from: "blocked", to: "leaked", cause: "no config change", degraded: true,
});
const run = (id, from, n) => Array.from({ length: n }, (_, i) => change(id, from + i));

const fl = [
  ...run("linux/claude", 1, 3),
  ...run("linux/gemini", 4, 2),
  ...run("darwin/codex", 6, 4),
  ...run("windows/copilot", 10, 5),
];

test("the tab list under a filter contains only identities from that OS", () => {
  assert.deepEqual(changeTabsForOs(fl, "linux"), [ALL_TAB, "linux/claude", "linux/gemini"],
    "a linux filter leaves All plus the two linux identities and nothing else");
  assert.deepEqual(changeTabsForOs(fl, "windows"), [ALL_TAB, "windows/copilot"],
    "a windows filter leaves All plus the one windows identity");
});

test("an identity with zero changes under the active filter gets no tab", () => {
  const tabs = changeTabsForOs(fl, "darwin");
  for (const gone of ["linux/claude", "linux/gemini", "windows/copilot"])
    assert.ok(!tabs.includes(gone), `${gone} has no darwin changes and must not keep an empty tab`);
  assert.deepEqual(tabs, [ALL_TAB, "darwin/codex"], "only the identity the filter admits keeps its tab");
});

test("unfiltered, every identity still gets its tab", () => {
  assert.deepEqual(changeTabsForOs(fl, OS_ALL),
    [ALL_TAB, "darwin/codex", "linux/claude", "linux/gemini", "windows/copilot"],
    "the all option must not drop any identity");
});

test("tab counts match the filtered set", () => {
  const count = (os, tab) => changesForTabInOs(fl, os, tab).length;
  assert.equal(count("linux", ALL_TAB), 5, "the All tab under a linux filter counts both linux identities");
  assert.equal(count("linux", "linux/claude"), 3, "per-identity counts are unchanged by the filter");
  assert.equal(count(OS_ALL, ALL_TAB), 14, "unfiltered, All counts the whole history");
  assert.equal(count("windows", ALL_TAB), 5, "the All tab under a windows filter counts only windows changes");
});

test("the listed changes under a tab respect the filter", () => {
  const got = changesForTabInOs(fl, "linux", ALL_TAB);
  assert.ok(got.every((f) => f.id.startsWith("linux/")),
    "no non-linux change may be listed under a linux filter");
  assert.equal(got[0].ts, "2026-01-05T00:00:00Z", "the filtered list is still newest first");
});

test("a tab outside the active filter lists nothing", () => {
  assert.deepEqual(changesForTabInOs(fl, "linux", "windows/copilot"), [],
    "the filter wins: an identity it excludes has no changes to list");
});

test("the two section filters do not share state", () => {
  let filters = newOsFilters();
  assert.equal(filters.latest.os, OS_ALL, "both sections start unfiltered");
  assert.equal(filters.flips.os, OS_ALL, "both sections start unfiltered");

  filters = setOsFilter(filters, "latest", "windows");
  assert.equal(filters.latest.os, "windows", "the top section took the new value");
  assert.equal(filters.flips.os, OS_ALL,
    "setting the top filter must leave the bottom section unfiltered");

  assert.ok(latestChangesForOs(fl, filters.latest.os).every((f) => f.id.startsWith("windows/")),
    "the top section is scoped to windows");
  assert.equal(cappedChangesForOs(fl, filters.flips.os).length, 14,
    "the bottom section still shows the whole history");
  assert.equal(changeTabsForOs(fl, filters.flips.os).length, 5,
    "and still shows every identity's tab");
});

test("setting the bottom filter leaves the top section's result unchanged", () => {
  let filters = newOsFilters();
  const topBefore = latestChangesForOs(fl, filters.latest.os).map((f) => f.id);

  filters = setOsFilter(filters, "flips", "darwin");
  assert.equal(filters.flips.os, "darwin", "the bottom section took the new value");
  assert.equal(filters.latest.os, OS_ALL,
    "setting the bottom filter must leave the top section unfiltered");

  assert.deepEqual(latestChangesForOs(fl, filters.latest.os).map((f) => f.id), topBefore,
    "the top section's items must be byte-identical before and after the bottom filter moved");
  assert.equal(changeCountForOs(fl, filters.flips.os), 4,
    "while the bottom section's N follows its own value");
  assert.deepEqual(changeTabsForOs(fl, filters.flips.os), [ALL_TAB, "darwin/codex"],
    "and its tablist follows its own value too");
});

test("each section keeps its own value when both are set", () => {
  let filters = setOsFilter(setOsFilter(newOsFilters(), "latest", "linux"), "flips", "windows");
  assert.equal(filters.latest.os, "linux", "the top value survives the bottom one being set");
  assert.equal(filters.flips.os, "windows", "and vice versa");
  assert.equal(latestChangesForOs(fl, filters.latest.os).length, 5, "top shows the 5 linux changes");
  assert.equal(cappedChangesForOs(fl, filters.flips.os).length, 5, "bottom shows the 5 windows changes");
});
