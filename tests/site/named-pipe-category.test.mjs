// Ticket #46: named_pipe_detection must fold into the ipc_sockets capability
// category (Windows equivalent of unix_socket_detection), not fall through to
// the uncounted "other" column. Run: node tests/site/named-pipe-category.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

// app.js is a plain <script> with no exports and a self-invoking boot() that
// touches the DOM/fetch. Strip everything from the boot section onward and
// export the pure functions/tables we need — no DOM, no fetch, no framework.
const pure = appJs.split("// ── boot")[0];
const loader = new Function(
  "module",
  "document",
  "getComputedStyle",
  `${pure}\nmodule.exports = { FT2CAT, CATEGORIES, cellStates, leakedCats };`
);
const mod = { exports: {} };
const stubDocument = { documentElement: {} };
const stubGetComputedStyle = () => ({ getPropertyValue: () => "" });
loader(mod, stubDocument, stubGetComputedStyle);
const { FT2CAT, CATEGORIES, cellStates, leakedCats } = mod.exports;

// -- acceptance: named_pipe_detection contributes to ipc_sockets, never "other" --
assert.equal(FT2CAT.named_pipe_detection, "ipc_sockets");

// -- acceptance: matrix stays 8 columns wide, ipc_sockets present once --
assert.equal(CATEGORIES.length, 8);
assert.equal(CATEGORIES.filter((c) => c.key === "ipc_sockets").length, 1);

function report(findings) {
  return { os: "windows", harness: "h", runTimestamp: "t", report: { findings, metadata: { tags: [] }, probeBinary: { commit: "c" } } };
}

// baseline has a named-pipe finding, harness's is empty -> blocked, not other.
const baseline = report([{ findingType: "named_pipe_detection", value: ["\\\\.\\pipe\\foo"] }]);
const blockedRow = report([{ findingType: "named_pipe_detection", value: [] }]);
const leaks = leakedCats(blockedRow);
assert.ok(!leaks.has("other"), "empty named_pipe_detection must not leak into other");
const states = cellStates(blockedRow, baseline);
assert.equal(states.ipc_sockets, "blocked");

// reverse: harness's is non-empty where baseline's was too -> leaked.
const leakedRow = report([{ findingType: "named_pipe_detection", value: ["\\\\.\\pipe\\foo"] }]);
assert.equal(cellStates(leakedRow, baseline).ipc_sockets, "leaked");

console.log("ok - named_pipe_detection folds into ipc_sockets category");
