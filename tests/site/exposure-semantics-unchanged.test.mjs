// Regression guard for the per-test-columns work. The matrix now shows one
// column per probe test, but the exposure number, the `exp.` column and the
// per-capability heatmap all still count LEAKED CAPABILITY CATEGORIES on a 0–8
// scale ("Exposure = number of leaked capability categories (0–8)" in
// index.html). Those are a different question from "which tests leaked", and
// the cheap way to break them is to widen CATEGORIES or to start mapping new
// finding types into FT2CAT so the count quietly moves.
// Run: node --test tests/site/exposure-semantics-unchanged.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

const pure = appJs.split("// ── boot")[0];
const loader = new Function("module", "document", "getComputedStyle",
  `${pure}\nmodule.exports = { CATEGORIES, FT2CAT, leakedCats, measuredCats, cellStates, build };`);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { CATEGORIES, FT2CAT, leakedCats, measuredCats, cellStates, build } = mod.exports;

const ft = (findingType, value) => ({ findingType, value });
const row = (harness, findings, ts = "2026-01-01T00:00:00Z") => ({
  os: "linux", harness, runTimestamp: ts,
  report: { findings, metadata: { tags: [] }, probeBinary: { commit: "c" } },
});

test("the capability category list is unchanged — eight, in order", () => {
  assert.deepEqual(CATEGORIES.map((c) => c.key), [
    "fs_read", "fs_write", "net_egress", "local_services",
    "ipc_sockets", "process_visibility", "host_mounts", "privileged",
  ], "the 0–8 exposure scale and the heatmap's y-axis are these eight keys");
  assert.equal(CATEGORIES.length, 8, "the chart hint promises a 0–8 range");
});

test("leakedCats still yields category keys, not finding types", () => {
  const leaks = leakedCats(row("h", [
    ft("sensitive_readable_paths", ["/etc/passwd"]),
    ft("ephemeral_writeable_paths", ["/dev/shm/x"]),
  ]));
  assert.ok(leaks.has("fs_read"), "a mapped finding type contributes its category");
  assert.ok(!leaks.has("sensitive_readable_paths"), "leakedCats speaks in categories");
  // ephemeral_writeable_paths has no FT2CAT entry, so it is "other" — which is
  // deliberately NOT one of the eight and so moves no exposure count.
  assert.ok(leaks.has("other"), "an unmapped capability finding is still visible as other");
  assert.ok(!leaks.has("fs_write"),
    "giving a new finding type a category here would silently move every exposure number");
});

test("FT2CAT maps only into the eight categories, and nothing new was added", () => {
  const catKeys = new Set(CATEGORIES.map((c) => c.key));
  for (const [k, v] of Object.entries(FT2CAT))
    assert.ok(catKeys.has(v), `${k} maps to ${v}, which is not one of the eight categories`);
  assert.deepEqual(Object.keys(FT2CAT).sort(), [
    "external_host_connectivity", "external_host_dns_resolution", "mounted_volumes_detections",
    "named_pipe_detection", "parent_process_detection", "process_detection",
    "sensitive_readable_paths", "tcp_ports_open", "udp_ports_open",
    "unix_socket_detection", "writeable_paths",
  ], "the category mapping is the per-test matrix's grouping key, not something it may extend");
});

test("measuredCats and cellStates still answer per category", () => {
  const r = row("h", [ft("writeable_paths", [])]);
  assert.deepEqual([...measuredCats(r)], ["fs_write"]);
  const st = cellStates(r, row("direct", [ft("writeable_paths", ["/a"])]));
  assert.deepEqual(Object.keys(st).sort(), CATEGORIES.map((c) => c.key).sort(),
    "cellStates is keyed by category and nothing else");
  assert.equal(st.fs_write, "blocked");
});

test("exposure counts leaked categories and stays within 0–8", () => {
  const all = [
    ft("sensitive_readable_paths", ["/etc/passwd"]), ft("writeable_paths", ["/tmp"]),
    ft("external_host_connectivity", ["1.1.1.1"]), ft("external_host_dns_resolution", ["example.com"]),
    ft("tcp_ports_open", [22]), ft("udp_ports_open", [53]),
    ft("unix_socket_detection", ["/run/docker.sock"]), ft("named_pipe_detection", ["\\\\.\\pipe\\x"]),
    ft("process_detection", ["init"]), ft("parent_process_detection", ["bash"]),
    ft("mounted_volumes_detections", ["/"]), ft("user_context_detection", { euid: 0 }),
    // an unmapped capability test and a context finding: neither may move the count
    ft("ephemeral_writeable_paths", ["/dev/shm/x"]), ft("hostname_detection", "box"),
  ];
  const model = build([row("direct", all), row("leaky", all)]);
  assert.equal(model["linux/leaky"][0].exposure, 8, "everything leaked is exactly 8, never 9");

  const none = build([row("direct", all), row("tight", all.map((f) =>
    f.findingType === "user_context_detection" ? ft(f.findingType, { euid: 1000 }) : ft(f.findingType, [])))]);
  assert.equal(none["linux/tight"][0].exposure, 0, "everything blocked is 0");
});
