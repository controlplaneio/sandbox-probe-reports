// Ticket #31: the five rootfs-swapping runtimes are retired from the comparison.
// The launcher must refuse them as unknown rather than launching them, and must
// describe only the runtimes it can still launch.
// Run: node tests/retired-runtimes.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(repo, "scripts", "run-probe-in-sandbox.sh");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "retired-runtimes-"));
const probe = path.join(tmp, "sandbox-probe"); // never executed: the launcher must bail first
fs.writeFileSync(probe, "");

const launch = (env) =>
  spawnSync("bash", [script], {
    cwd: tmp,
    encoding: "utf8",
    env: { ...process.env, PROBE: probe, OUT: path.join(tmp, "report.json"), ...env },
  });

for (const runtime of ["docker", "podman", "bwrap", "nspawn", "gvisor"]) {
  const r = launch({ RUNTIME: runtime, ROOTFS: tmp });
  const output = r.stdout + r.stderr;
  assert.notEqual(r.status, 0, `${runtime} must not launch`);
  assert.match(output, new RegExp(`unknown RUNTIME '${runtime}'`), `${runtime} must be rejected as unknown, got: ${output}`);
}

// -- the launcher's own description lists only what it can still launch --
const usage = launch({}).stderr;
assert.match(usage, /RUNTIME \(srt\|firejail\|nono\) is required/, `usage must list only the remaining runtimes, got: ${usage}`);

const header = fs.readFileSync(script, "utf8").split("set -eo pipefail")[0];
for (const runtime of ["podman", "nspawn", "gvisor", "runsc"]) {
  assert.ok(!new RegExp(`^#   ${runtime}\\b`, "m").test(header), `${runtime} must not be documented as selectable`);
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log("ok - retired runtimes are unknown to the sandbox launcher");
