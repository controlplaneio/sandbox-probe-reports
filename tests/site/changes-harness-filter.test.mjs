// Pins the harness filter that sits alongside the OS filter on both changes
// sections. The two compose as AND inside a section, and the harness options are
// scoped to that section's current OS so a dead combination cannot be chosen at
// all — picking windows must leave only the harnesses that actually ran on
// windows, and a harness the new OS never ran falls back to "all" rather than
// staying selected and matching nothing.
//
// Every cap, count, threshold and tab is computed on the DOUBLY filtered set.
// Capping before the filters, or computing the N on the OS-only set, shows fewer
// items than the cap (or offers more than the panel lists) while looking
// entirely correct — the same failure the OS-only tests were written against,
// one filter later.
// Run: node --test tests/site/changes-harness-filter.test.mjs
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
  `${pure}\nmodule.exports = { harnessOptions, harnessOfChange, changesInSel,
     latestChangesForSel, cappedChangesForSel, needsMoreForSel, changeCountForSel,
     changeTabsForSel, changesForTabInSel, noChangesNote,
     newChangeFilters, setChangeFilter,
     OS_ALL, HARNESS_ALL, ALL_TAB, LATEST_CHANGES_CAP, ALL_CHANGES_CAP };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const {
  harnessOptions, harnessOfChange, changesInSel,
  latestChangesForSel, cappedChangesForSel, needsMoreForSel, changeCountForSel,
  changeTabsForSel, changesForTabInSel, noChangesNote,
  newChangeFilters, setChangeFilter,
  OS_ALL, HARNESS_ALL, ALL_TAB, LATEST_CHANGES_CAP, ALL_CHANGES_CAP,
} = mod.exports;

const change = (id, day) => ({
  id, ts: `2026-01-${String(day).padStart(2, "0")}T00:00:00Z`,
  cat: "FS read", from: "blocked", to: "leaked", cause: "no config change", degraded: true,
});
const run = (id, from, n) => Array.from({ length: n }, (_, i) => change(id, from + i));

// A three-OS matrix in which codex is the only harness that ran everywhere,
// claude-sandbox is linux-only and copilot is windows-only — so "scoped to the
// selected OS" has something to actually exclude.
const rows = [
  { os: "linux", harness: "claude-sandbox" }, { os: "linux", harness: "codex" },
  { os: "linux", harness: "gemini-sandbox-exec" }, { os: "linux", harness: "direct" },
  { os: "darwin", harness: "codex" }, { os: "darwin", harness: "gemini-sandbox-exec" },
  { os: "darwin", harness: "direct" },
  { os: "windows", harness: "copilot" }, { os: "windows", harness: "codex" },
];

const fl = [
  ...run("linux/claude-sandbox", 1, 3),
  ...run("linux/codex", 4, 2),
  ...run("darwin/codex", 6, 4),
  ...run("darwin/gemini-sandbox-exec", 10, 2),
  ...run("windows/copilot", 12, 5),
  ...run("windows/codex", 17, 3),
];

const sel = (os = OS_ALL, harness = HARNESS_ALL) => ({ os, harness });

// ── options ───────────────────────────────────────────────────────────────────

test("the harness option list is derived from the report data, never hardcoded", () => {
  assert.deepEqual(harnessOptions(rows, OS_ALL),
    ["claude-sandbox", "codex", "copilot", "gemini-sandbox-exec"],
    "every harness present in the data gets exactly one option, sorted, baseline aside");
});

test("the harness option list does not depend on the arrival order of the reports", () => {
  const shuffled = [...rows].reverse();
  assert.deepEqual(harnessOptions(shuffled, OS_ALL), harnessOptions(rows, OS_ALL),
    "the option list must be sorted, not first-seen order");
});

test("the direct baseline is not offered as a harness", () => {
  assert.ok(!harnessOptions(rows, OS_ALL).includes("direct"),
    "/direct carries no changes of its own, so offering it would be a dead option");
  assert.ok(!harnessOptions(rows, "linux").includes("direct"),
    "and it stays out under an OS scope too");
});

test("harness options are scoped to the selected OS", () => {
  assert.deepEqual(harnessOptions(rows, "windows"), ["codex", "copilot"],
    "only the harnesses that actually ran on windows may be offered");
  assert.deepEqual(harnessOptions(rows, "darwin"), ["codex", "gemini-sandbox-exec"],
    "and only the darwin ones under darwin");
});

test("a linux-only harness is absent from the options when the OS is windows", () => {
  assert.ok(harnessOptions(rows, "linux").includes("claude-sandbox"),
    "claude-sandbox ran on linux, so linux offers it");
  assert.ok(!harnessOptions(rows, "windows").includes("claude-sandbox"),
    "claude-sandbox never ran on windows, so the dead combination cannot be chosen");
});

test("the harness of a change is everything after the first slash of its identity", () => {
  assert.equal(harnessOfChange(change("windows/copilot", 1)), "copilot");
  assert.equal(harnessOfChange(change("darwin/gemini-sandbox-exec", 1)), "gemini-sandbox-exec");
  assert.equal(harnessOfChange(change("linux/claude-sandbox", 1)), "claude-sandbox");
});

// ── filtering, and composition ────────────────────────────────────────────────

test("selecting a harness returns only that harness, across every OS", () => {
  const got = changesInSel(fl, sel(OS_ALL, "codex"));
  assert.equal(got.length, 9, "the 2 linux + 4 darwin + 3 windows codex changes all survive");
  assert.ok(got.every((f) => harnessOfChange(f) === "codex"),
    "no other harness may appear under a codex filter");
  assert.deepEqual([...new Set(got.map((f) => f.id.split("/")[0]))].sort(), ["darwin", "linux", "windows"],
    "with the OS unset the harness filter must reach across all three OSes");
});

test("the harness all sentinel excludes nothing", () => {
  assert.equal(changesInSel(fl, sel("darwin", HARNESS_ALL)).length, 6,
    "darwin with no harness selected keeps both darwin identities");
  assert.equal(changesInSel(fl, sel()).length, 19, "neither filter set keeps the whole history");
});

test("the two filters compose as AND, not OR", () => {
  const got = changesInSel(fl, sel("windows", "codex"));
  assert.equal(got.length, 3, "only the three windows/codex changes satisfy both filters");
  assert.ok(got.every((f) => f.id === "windows/codex"),
    "an OR would also admit linux/codex, darwin/codex and windows/copilot");
});

test("an impossible combination returns empty rather than falling back to something broader", () => {
  assert.deepEqual(changesInSel(fl, sel("windows", "claude-sandbox")), [],
    "claude-sandbox never ran on windows, so the answer is nothing — not all windows, not all claude-sandbox");
  assert.deepEqual(changesInSel(fl, sel("linux", "copilot")), [],
    "and the same the other way round");
});

test("a harness name is matched exactly, not as a prefix", () => {
  const extra = [...fl, ...run("linux/codex-cli", 20, 2)];
  const got = changesInSel(extra, sel("linux", "codex"));
  assert.equal(got.length, 2, "codex must not swallow codex-cli");
  assert.ok(got.every((f) => f.id === "linux/codex"), "only the exact identity matches");
});

// ── caps, counts and thresholds on the doubly filtered set ────────────────────

// The shape that separates "cap then filter" from "filter then cap": the pair
// under test is entirely OLDER than the noise, so the unfiltered newest N
// contains none of it.
const pairOldRestNew = (nPair, nNoise) => [
  ...run("windows/codex", 1, nPair),
  ...run("windows/copilot", 1 + nPair, nNoise),
  ...run("linux/codex", 1 + nPair + nNoise, nNoise),
];

test("the top cap is applied after BOTH filters, not before", () => {
  // 12 windows/codex changes, all older than 30 windows/copilot and 30 linux/codex
  // ones: both the unfiltered and the OS-only newest 10 contain none of them.
  const fl2 = pairOldRestNew(12, 30);
  const got = latestChangesForSel(fl2, sel("windows", "codex"));
  assert.equal(got.length, LATEST_CHANGES_CAP,
    "the top section must show 10 of the 12 doubly-filtered changes, not 10 of a broader set filtered down");
  assert.ok(got.every((f) => f.id === "windows/codex"),
    "every item shown under windows + codex must be a windows/codex change");
  assert.equal(got[0].ts, "2026-01-12T00:00:00Z", "the filtered set is still ordered newest first");
});

test("the bottom cap is applied after BOTH filters, not before", () => {
  const fl2 = pairOldRestNew(30, 40);
  const got = cappedChangesForSel(fl2, sel("windows", "codex"));
  assert.equal(got.length, ALL_CHANGES_CAP,
    "the bottom section must show 25 of the 30 doubly-filtered changes");
  assert.ok(got.every((f) => f.id === "windows/codex"),
    "every item in the capped bottom list must come from both active filters");
});

test("the N in the button counts the doubly filtered set, not the OS-only one", () => {
  const fl2 = pairOldRestNew(26, 40);
  assert.equal(changeCountForSel(fl2, sel("windows", "codex")), 26,
    "the button must offer the 26 changes both filters admit");
  assert.equal(changeCountForSel(fl2, sel("windows", HARNESS_ALL)), 66,
    "while the OS-only count is a different, larger number");
  assert.equal(changeCountForSel(fl2, sel()), 106, "and unfiltered it is the whole history");
});

test("the 25-boundary is computed on the doubly filtered set — 25 offers nothing more", () => {
  const fl2 = pairOldRestNew(25, 100);
  assert.equal(needsMoreForSel(fl2, sel("windows", "codex")), false,
    "all 25 windows/codex changes are already on the page, so there is nothing more to open");
  assert.equal(needsMoreForSel(fl2, sel("windows", HARNESS_ALL)), true,
    "the OS-only set does exceed the cap, which is exactly the wrong set to test");
});

test("the 25-boundary is computed on the doubly filtered set — 26 offers more", () => {
  const fl2 = pairOldRestNew(26, 100);
  assert.equal(needsMoreForSel(fl2, sel("windows", "codex")), true,
    "26 changes inside both filters exceed the cap, so the expanded view must be offered");
});

test("a combination with no changes offers no more affordance and no items", () => {
  assert.deepEqual(latestChangesForSel(fl, sel("windows", "claude-sandbox")), [],
    "an impossible pair means no items");
  assert.equal(needsMoreForSel(fl, sel("windows", "claude-sandbox")), false,
    "an empty filtered list must not offer more");
  assert.equal(changeCountForSel(fl, sel("windows", "claude-sandbox")), 0, "and N must be zero");
});

// ── tabs ──────────────────────────────────────────────────────────────────────

test("the tab list respects both filters", () => {
  assert.deepEqual(changeTabsForSel(fl, sel(OS_ALL, "codex")),
    [ALL_TAB, "darwin/codex", "linux/codex", "windows/codex"],
    "a codex filter leaves All plus the three codex identities and nothing else");
  assert.deepEqual(changeTabsForSel(fl, sel("darwin", "codex")), [ALL_TAB, "darwin/codex"],
    "adding the OS narrows it to the one identity that satisfies both");
});

test("an identity excluded by EITHER filter gets no tab", () => {
  const tabs = changeTabsForSel(fl, sel("windows", "codex"));
  for (const gone of ["windows/copilot", "linux/codex", "darwin/codex", "linux/claude-sandbox"])
    assert.ok(!tabs.includes(gone),
      `${gone} fails at least one of the two filters and must not keep a tab that opens on nothing`);
  assert.deepEqual(tabs, [ALL_TAB, "windows/codex"], "only the identity both filters admit keeps its tab");
});

test("tab counts are computed on the doubly filtered set", () => {
  const count = (s, tab) => changesForTabInSel(fl, s, tab).length;
  assert.equal(count(sel(OS_ALL, "codex"), ALL_TAB), 9, "All under a codex filter counts all three codex identities");
  assert.equal(count(sel("windows", "codex"), ALL_TAB), 3, "adding windows drops it to the windows/codex changes");
  assert.equal(count(sel("windows", "codex"), "windows/codex"), 3, "the per-identity count agrees with All here");
  assert.equal(count(sel("windows", HARNESS_ALL), ALL_TAB), 8,
    "while the OS-only count is a different number — 8, not 3");
});

test("a tab outside either filter lists nothing", () => {
  assert.deepEqual(changesForTabInSel(fl, sel("windows", "codex"), "windows/copilot"), [],
    "the harness filter wins even though the OS matches");
  assert.deepEqual(changesForTabInSel(fl, sel("windows", "codex"), "linux/codex"), [],
    "and the OS filter wins even though the harness matches");
});

// ── selection state, and the fallback ─────────────────────────────────────────

test("both sections start with both filters unset", () => {
  const filters = newChangeFilters();
  for (const section of ["latest", "flips"]) {
    assert.equal(filters[section].os, OS_ALL, `${section} starts with no OS selected`);
    assert.equal(filters[section].harness, HARNESS_ALL, `${section} starts with no harness selected`);
  }
});

test("the two sections' harness values do not share state", () => {
  let filters = setChangeFilter(newChangeFilters(), "latest", { harness: "codex" }, rows);
  assert.equal(filters.latest.harness, "codex", "the top section took the new harness");
  assert.equal(filters.flips.harness, HARNESS_ALL,
    "setting the top harness must leave the bottom section unfiltered");
  filters = setChangeFilter(filters, "flips", { harness: "copilot" }, rows);
  assert.equal(filters.latest.harness, "codex", "and the top value survives the bottom one being set");
  assert.equal(filters.flips.harness, "copilot", "while the bottom takes its own");
});

test("the harness selection falls back to all when the new OS does not carry it", () => {
  let filters = setChangeFilter(newChangeFilters(), "flips", { harness: "claude-sandbox" }, rows);
  assert.equal(filters.flips.harness, "claude-sandbox", "claude-sandbox is selected while unscoped");
  filters = setChangeFilter(filters, "flips", { os: "windows" }, rows);
  assert.equal(filters.flips.os, "windows", "the new OS is taken");
  assert.equal(filters.flips.harness, HARNESS_ALL,
    "claude-sandbox never ran on windows, so it must fall back to all rather than match nothing");
  assert.equal(changesInSel(fl, filters.flips).length, 8,
    "and the section shows every windows change, not an empty list");
});

test("a harness the new OS does carry survives the OS change", () => {
  let filters = setChangeFilter(newChangeFilters(), "flips", { harness: "codex" }, rows);
  filters = setChangeFilter(filters, "flips", { os: "windows" }, rows);
  assert.equal(filters.flips.harness, "codex",
    "codex ran on windows, so the selection is still meaningful and must be kept");
  assert.equal(changesInSel(fl, filters.flips).length, 3, "and the composed filter is still in force");
});

test("the fallback only touches the section whose OS moved", () => {
  let filters = setChangeFilter(newChangeFilters(), "latest", { harness: "claude-sandbox" }, rows);
  filters = setChangeFilter(filters, "flips", { os: "windows" }, rows);
  assert.equal(filters.latest.harness, "claude-sandbox",
    "the top section's harness is still valid under its own (unset) OS and must not be reset");
  assert.equal(filters.latest.os, OS_ALL, "nor may its OS move");
});

test("clearing the OS back to all does not clear the harness", () => {
  let filters = setChangeFilter(newChangeFilters(), "flips", { os: "windows" }, rows);
  filters = setChangeFilter(filters, "flips", { harness: "codex" }, rows);
  filters = setChangeFilter(filters, "flips", { os: OS_ALL }, rows);
  assert.equal(filters.flips.harness, "codex",
    "every OS carries the harness under the all option, so there is nothing dead to clear");
  assert.equal(changesInSel(fl, filters.flips).length, 9, "and the harness filter still reaches all three OSes");
});

// ── empty state, and purity ───────────────────────────────────────────────────

test("the empty state names the harness that is hiding the history", () => {
  const note = noChangesNote(sel(OS_ALL, "copilot"));
  assert.match(note, /copilot/, "the note must name the harness being filtered to");
  assert.match(note, /filter/i, "the note must attribute the emptiness to the filter");
});

test("the empty state names both filters when both are set", () => {
  const note = noChangesNote(sel("windows", "claude-sandbox"));
  assert.match(note, /windows/, "the note must name the OS");
  assert.match(note, /claude-sandbox/, "and the harness");
  assert.match(note, /filter/i, "and say the filters caused it");
});

test("the unfiltered empty state wording is unchanged", () => {
  assert.equal(noChangesNote(sel()), "No flips yet.",
    "with neither filter set this is genuinely no history, not a hidden one");
});

test("filtering does not mutate the change list it is given", () => {
  const before = fl.map((f) => f.ts);
  cappedChangesForSel(fl, sel("windows", "codex"));
  latestChangesForSel(fl, sel(OS_ALL, "codex"));
  changeTabsForSel(fl, sel("darwin", "codex"));
  assert.deepEqual(fl.map((f) => f.ts), before,
    "the three views share one list, so none of them may reorder or splice it");
});

// An identity is "<os>/<harness>", split on the FIRST slash only. Nothing in
// the current matrix carries a slash in its name, so a split("/")[1] reading
// passes every other test here while silently truncating the first such
// identity to its leading segment. Pin the whole remainder.
test("the harness is everything after the first slash, not the second segment", () => {
  assert.equal(harnessOfChange(change("linux/gemini/docker", 1)), "gemini/docker",
    "a harness name containing a slash must survive whole");
  assert.equal(harnessOfChange(change("darwin/gemini-sandbox-exec", 1)), "gemini-sandbox-exec",
    "and an ordinary hyphenated name is unaffected");
});
