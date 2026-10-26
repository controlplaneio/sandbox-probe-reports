// Copilot's Windows sandbox stopped engaging on GitHub's hosted runners: on
// windows-2025-vs2026 with Copilot 1.0.102 it prints "Sandboxing is disabled
// for this session because this host does not support it ... requires Windows
// BaseContainer" and runs unsandboxed. The report that follows is honest but
// indistinguishable from a silent regression, so the launcher records the
// agent's own sentence and the assert step reads it. These tests pin that
// sentence: widen it and a silent regression starts passing.
// Run: node --test tests/copilot-host-refused-sandbox.test.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const common = path.join(here, "..", "scripts", "stub-common.sh");

// Source the real helper and run it against a log file, so the test exercises
// the shipped code rather than a copy of its regex.
const refused = (logText) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "refused-"));
  try {
    const log = path.join(dir, "copilot.log");
    fs.writeFileSync(log, logText);
    const out = execFileSync("bash", ["-c",
      `set -e; . "${common}" >/dev/null 2>&1 || true
       if stub_host_refused_sandbox "${log}"; then echo yes; else echo no; fi`],
      { encoding: "utf8" });
    return out.trim().endsWith("yes");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
};

const REAL_WARNING =
  "Warning: Sandboxing is disabled for this session because this host does not support it. " +
  "Shell commands and sandboxed services will run unsandboxed. Your saved sandbox setting " +
  "remains unchanged. Command sandboxing requires Windows BaseContainer. Update Windows";

test("the sentence Copilot 1.0.102 actually printed is recognised", () => {
  assert.equal(refused(`some output\n${REAL_WARNING}\nmore output\n`), true,
    "this is the verbatim line from run 39766850096; it must match");
});

test("the BaseContainer half alone is enough", () => {
  assert.equal(refused("Command sandboxing requires Windows BaseContainer.\n"), true,
    "the wording around it may change; the requirement naming the mechanism should still count");
});

test("a run with no such warning is NOT treated as a host refusal", () => {
  assert.equal(refused("GitHub Copilot CLI 1.0.102.\nRunning the probe.\ndone\n"), false,
    "a sandbox that silently stops engaging must still fail the assert step");
});

test("merely mentioning the sandbox is not a refusal", () => {
  assert.equal(refused("sandbox=on\nsandboxing enabled for this session\n"), false,
    "the marker must need the refusal, not the word sandbox");
});

test("an empty or missing log is not a refusal", () => {
  assert.equal(refused(""), false, "no evidence is not evidence of a host limitation");
});
