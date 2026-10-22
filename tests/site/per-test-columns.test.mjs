// The Comparison matrix shows the full list of tests — one column per probe
// finding type, always — rather than the eight rolled-up capability categories.
// This pins the three things that can silently go wrong with that:
//   1. the column list is DERIVED from the loaded reports, so a probe release
//      that adds a test gets a column with no code change and a retired test
//      loses one (the same reasoning as identity arrival in build() and the
//      change tabs in changeTabs());
//   2. the order is deterministic and groups related tests together, because a
//      column order that depends on which report happened to be read first
//      reshuffles the table between deploys while looking entirely correct;
//   3. the per-test cell keeps the baseline normalisation and the four states —
//      a cell that cannot distinguish "the baseline could not do this either"
//      from "the sandbox closed the door" is the failure that made an
//      unmeasured cell render as a security claim.
// Run: node --test tests/site/per-test-columns.test.mjs
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
  `${pure}\nmodule.exports = { testColumns, testLabel, testCellStates, CATEGORIES, FT2CAT, CONTEXT_FT };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { testColumns, testLabel, testCellStates, CATEGORIES, FT2CAT, CONTEXT_FT } = mod.exports;

const row = (harness, findings, os = "linux") => ({
  os, harness, runTimestamp: "2026-01-01T00:00:00Z",
  report: { findings, metadata: { tags: [] }, probeBinary: { commit: "c" } },
});
const ft = (findingType, value) => ({ findingType, value });
const keys = (rows) => testColumns(rows).map((c) => c.key);

// ── 1. derived from the data, never hardcoded ─────────────────────────────────

test("a finding type nobody hardcoded still gets its own column", () => {
  const cols = testColumns([row("h", [ft("brand_new_probe_test", ["x"])])]);
  const k = cols.map((c) => c.key);
  assert.ok(k.includes("brand_new_probe_test"),
    "a finding type absent from FT2CAT must still get a column — the list is derived from the data");
  // and only what the data carried, plus the derived privileged column
  assert.deepEqual(k, ["brand_new_probe_test", "privileged"],
    "columns are exactly the finding types present in the reports, plus privileged");
});

test("a retired test loses its column with no code change", () => {
  const before = keys([row("h", [ft("writeable_paths", []), ft("retired_test", [])])]);
  const after = keys([row("h", [ft("writeable_paths", [])])]);
  assert.ok(before.includes("retired_test"), "sanity: the test was present while the data carried it");
  assert.ok(!after.includes("retired_test"),
    "a finding type no longer emitted by the probe must not leave an empty column behind");
});

test("the union spans every loaded report, not just the first", () => {
  const k = keys([
    row("a", [ft("writeable_paths", [])]),
    row("b", [ft("tcp_ports_open", [])]),
    row("c", [ft("sensitive_readable_paths", [])], "windows"),
  ]);
  for (const want of ["writeable_paths", "tcp_ports_open", "sensitive_readable_paths"])
    assert.ok(k.includes(want), `${want} appears in one report and so must get a column`);
});

test("context-only finding types never get a column", () => {
  const contextRows = [row("h", [...CONTEXT_FT].map((c) => ft(c, { any: "value" })))];
  const k = keys(contextRows);
  for (const c of CONTEXT_FT)
    assert.ok(!k.includes(c), `${c} is context, not a capability test, and must not be a column`);
  assert.deepEqual(k, ["privileged"],
    "a report carrying only context findings yields no test columns");
});

test("ephemeral_writeable_paths is its own column, distinct from writeable_paths", () => {
  const k = keys([row("h", [ft("writeable_paths", ["/tmp/a"]), ft("ephemeral_writeable_paths", ["/dev/shm/b"])])]);
  assert.ok(k.includes("writeable_paths"), "writeable_paths keeps its column");
  assert.ok(k.includes("ephemeral_writeable_paths"),
    "ephemeral_writeable_paths (probe v6.15.1) is a separate test and must not be folded into writeable_paths");
  assert.equal(new Set(k).size, k.length, "no column key appears twice");
});

test("named-pipe reachability gets a column even though FT2CAT has no entry for it", () => {
  const k = keys([row("h", [ft("named_pipe_reachability", ["\\\\.\\pipe\\foo"])], "windows")]);
  assert.ok(k.includes("named_pipe_reachability"),
    "an unmapped IPC test must surface as its own column rather than vanishing into a rolled-up category");
});

// ── 2. deterministic ordering, grouped by category ───────────────────────────

const ORDER_ROWS = [row("h", [
  ft("mounted_volumes_detections", []), ft("zz_unmapped", []),
  ft("tcp_ports_open", []), ft("sensitive_readable_paths", []),
  ft("external_host_dns_resolution", []), ft("aaa_unmapped", []),
  ft("writeable_paths", []), ft("udp_ports_open", []),
  ft("external_host_connectivity", []),
])];
const EXPECTED_ORDER = [
  "sensitive_readable_paths",                                     // fs_read
  "writeable_paths",                                              // fs_write
  "external_host_connectivity", "external_host_dns_resolution",   // net_egress, alpha within
  "tcp_ports_open", "udp_ports_open",                             // local_services, alpha within
  "mounted_volumes_detections",                                   // host_mounts
  "aaa_unmapped", "zz_unmapped",                                  // no category: last, alpha
  "privileged",                                                   // derived, very last
];

test("columns group by their FT2CAT category in CATEGORIES order, alphabetically within a group", () => {
  assert.deepEqual(keys(ORDER_ROWS), EXPECTED_ORDER,
    "related tests must sit together, in the same category order the exposure chart uses");
});

test("column order does not depend on the order the findings arrive in", () => {
  const shuffled = [row("h", [...ORDER_ROWS[0].report.findings].reverse())];
  assert.deepEqual(keys(shuffled), EXPECTED_ORDER,
    "the column list must be sorted, not first-seen order");
});

test("uncategorised tests sort after every categorised one, and privileged is last", () => {
  const k = keys(ORDER_ROWS);
  assert.equal(k.at(-1), "privileged", "privileged is derived rather than a finding type, so it ends the row");
  assert.ok(k.indexOf("aaa_unmapped") > k.indexOf("mounted_volumes_detections"),
    "a test with no category sorts after every test that has one, whatever its name");
});

test("each column carries its raw finding type for the header title", () => {
  const col = testColumns(ORDER_ROWS).find((c) => c.key === "mounted_volumes_detections");
  assert.equal(col.ft, "mounted_volumes_detections",
    "the raw finding type must survive on the column so the header can expose it on hover");
  assert.equal(FT2CAT[col.ft], "host_mounts", "and the category it grouped under stays readable");
  const priv = testColumns(ORDER_ROWS).at(-1);
  assert.equal(priv.ft, undefined, "the privileged column has no finding type of its own");
});

// ── 3. readable headers derived from the finding type ────────────────────────

test("labels are derived from the finding type, not looked up", () => {
  assert.equal(testLabel("sensitive_readable_paths"), "Sensitive readable paths");
  assert.equal(testLabel("ephemeral_writeable_paths"), "Ephemeral writeable paths");
  assert.equal(testLabel("mounted_volumes_detections"), "Mounted volumes",
    "a trailing detection/detections says nothing and costs header width");
  assert.equal(testLabel("unix_socket_detection"), "Unix socket");
  assert.equal(testLabel("tcp_ports_open"), "TCP ports open", "acronyms read as acronyms");
  assert.equal(testLabel("external_host_dns_resolution"), "External host DNS resolution");
  assert.equal(testLabel("a_test_invented_tomorrow"), "A test invented tomorrow",
    "an unseen finding type still gets a readable label");
});

// ── 4. per-test cell state, baseline-normalised ──────────────────────────────

const COLS = testColumns([row("h", [ft("writeable_paths", [])])]);
const states = (rowFindings, baseFindings) =>
  testCellStates(row("h", rowFindings), baseFindings === null ? null : row("direct", baseFindings), COLS);

test("a test both the baseline and the row could do reads leaked", () => {
  assert.equal(states([ft("writeable_paths", ["/tmp/a"])], [ft("writeable_paths", ["/tmp/a"])]).writeable_paths,
    "leaked");
});

test("a test the baseline could do and the row could not reads blocked", () => {
  assert.equal(states([ft("writeable_paths", [])], [ft("writeable_paths", ["/tmp/a"])]).writeable_paths,
    "blocked");
});

test("a test the baseline could not do is na, not blocked or leaked", () => {
  // the baseline ran the task and found nothing: there is nothing for the
  // sandbox to block, so the cell must not claim either outcome.
  assert.equal(states([ft("writeable_paths", [])], [ft("writeable_paths", [])]).writeable_paths, "na",
    "no achievability in the baseline means nothing to prove");
  assert.equal(states([ft("writeable_paths", ["/tmp/a"])], [ft("writeable_paths", [])]).writeable_paths, "na",
    "without baseline normalisation this would read leaked");
});

test("a test absent from the row is unprovable, not blocked", () => {
  assert.equal(states([], [ft("writeable_paths", ["/tmp/a"])]).writeable_paths, "unprovable",
    "a task that never ran emits no finding; scoring that as blocked turns a failed scan into a security claim");
});

test("a test absent from the baseline is unprovable", () => {
  assert.equal(states([ft("writeable_paths", ["/tmp/a"])], []).writeable_paths, "unprovable",
    "achievability cannot be established from a baseline scan that never ran");
});

test("with no baseline at all every test column is unprovable", () => {
  const st = states([ft("writeable_paths", ["/tmp/a"])], null);
  assert.equal(st.writeable_paths, "unprovable");
});

test("the four states are exactly the existing leaked/blocked/na/unprovable set", () => {
  const seen = new Set([
    states([ft("writeable_paths", ["/a"])], [ft("writeable_paths", ["/a"])]).writeable_paths,
    states([ft("writeable_paths", [])], [ft("writeable_paths", ["/a"])]).writeable_paths,
    states([ft("writeable_paths", [])], [ft("writeable_paths", [])]).writeable_paths,
    states([], [ft("writeable_paths", ["/a"])]).writeable_paths,
  ]);
  assert.deepEqual([...seen].sort(), ["blocked", "leaked", "na", "unprovable"]);
});

test("empty is a measured negative, not an absent measurement", () => {
  // `writeable_paths: []` is a task that ran and found nothing — the whole
  // point of the baseline comparison — and must not collapse onto unprovable.
  assert.equal(states([ft("writeable_paths", [])], [ft("writeable_paths", ["/a"])]).writeable_paths, "blocked");
  assert.equal(states([], [ft("writeable_paths", ["/a"])]).writeable_paths, "unprovable");
});

// ── 5. the privileged column keeps its special case ──────────────────────────

test("the privileged column still derives from user_context_detection", () => {
  const base = [ft("writeable_paths", ["/a"])];
  assert.equal(states([ft("user_context_detection", { euid: 0 })], base).privileged, "leaked",
    "euid 0 is root and reads leaked");
  assert.equal(states([ft("user_context_detection", { euid: 1000 })], base).privileged, "blocked",
    "a non-zero euid reads blocked");
});

test("the privileged column is unprovable when user_context_detection is absent", () => {
  assert.equal(states([ft("writeable_paths", [])], [ft("writeable_paths", ["/a"])]).privileged, "unprovable",
    "absent euid means unmeasured, not non-root");
});

test("privileged ignores the baseline, as it always has", () => {
  assert.equal(states([ft("user_context_detection", { euid: 0 })], null).privileged, "leaked",
    "root is root whether or not a baseline exists");
});

// ── 6. the matrix is wider than the categories, by construction ──────────────

test("the per-test matrix is not the eight-category matrix", () => {
  const cols = testColumns([row("h", [
    ft("sensitive_readable_paths", []), ft("writeable_paths", []), ft("ephemeral_writeable_paths", []),
    ft("tcp_ports_open", []), ft("udp_ports_open", []), ft("unix_socket_detection", []),
  ])]);
  const testCols = cols.filter((c) => c.ft);
  const cats = new Set(testCols.map((c) => c.cat));
  assert.equal(testCols.length, 6, "all six tests get a column");
  assert.ok(cats.size < testCols.length,
    "folding them into categories would show fewer columns than there are tests; the matrix must show every test");
  assert.ok(CATEGORIES.length === 8, "and the eight categories remain the exposure unit, not the column unit");
});
