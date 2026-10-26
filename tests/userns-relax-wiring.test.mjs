// Every Linux row whose sandbox needs a capability-bearing user namespace must run the relax
// script, and no row may keep a hand-rolled copy of the sysctl: ubuntu-latest moved to
// ubuntu-26.04 and the single-knob version read as applied while the rows still failed.
// Run: node --test tests/userns-relax-wiring.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const wf = fs.readFileSync(path.join(here, "..", ".github", "workflows", "scan-matrix.yaml"), "utf8");
const script = "scripts/linux-allow-capability-bearing-userns.sh";

test("the relax script exists and is executable", () => {
  const p = path.join(here, "..", script);
  assert.ok(fs.existsSync(p), `${script} must exist`);
  assert.ok(fs.statSync(p).mode & 0o111, "it is invoked directly, so it must be executable");
});

test("every Linux sandbox setup step calls it", () => {
  const calls = wf.split(script).length - 1;
  // Four today: the bwrap deps step (claude/codex/copilot), the srt install, and the two nono
  // installs. The floor is what matters — the strict guard is the no-inline-sysctl test below,
  // which is what catches a NEW step rolling its own copy.
  assert.ok(calls >= 4,
    `expected every userns-dependent setup step to call ${script}, found ${calls}; a row that ` +
    "skips it fails with 'nested userns is capability-restricted'");
});

test("no step hand-rolls the sysctl any more", () => {
  assert.ok(!/sysctl -w kernel\.apparmor_restrict/.test(wf),
    "clearing one knob inline is what silently stopped working on ubuntu-26.04; the script " +
    "clears every related knob and proves the result");
});

test("the script clears the unconfined knob too, not just the documented one", () => {
  const body = fs.readFileSync(path.join(here, "..", script), "utf8");
  assert.match(body, /kernel\.apparmor_restrict_unprivileged_userns/);
  assert.match(body, /kernel\.apparmor_restrict_unprivileged_unconfined/,
    "the documented knob alone read as applied while the rows still failed");
});
