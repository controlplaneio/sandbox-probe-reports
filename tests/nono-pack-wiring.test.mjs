// Ticket #27/#29: installing a nono registry pack mutates the machine it runs on — it splices
// Codex plugin wiring into ~/.codex on install, even under --dry-run. The properties that keep
// that safe are ORDERING properties in shell, and the run that would prove them needs a real
// registry, a real pack and a real mutation of somebody's home directory. That run is exercised
// behind the same gating as the other side-effecting jobs (scan-matrix.yaml, the `attest` job's
// fault-injection step). This is the half that can run on every push: it reads every caller
// the way tests/vendor-default-flags.test.mjs reads the sandbox launcher, and fails in the pull
// request that reorders them.
//
// Run: node tests/nono-pack-wiring.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scripts = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts");
const read = (name) => fs.readFileSync(path.join(scripts, name), "utf8");

// Every script that installs a pack owes the same three things, in this order.
const CALLERS = ["attest-profile.sh", "run-probe-via-codex-stub.sh"];

// `nono pull` is the install; nothing may precede it but the warning and the snapshot+trap.
const at = (source, needle) => {
  const i = source.indexOf(needle);
  assert.notEqual(i, -1, `expected to find ${needle}`);
  return i;
};

for (const name of CALLERS) {
  const source = read(name);
  const warn = at(source, "nono_pack_warn");
  const arm = at(source, "nono_pack_arm");
  const trap = at(source, "trap nono_pack_restore EXIT");
  const install = at(source, "nono_pack_install");

  assert.ok(warn < install, `${name}: the machine must be warned before the pack is installed`);
  assert.ok(arm < install, `${name}: the before-snapshot must be taken before the pack is installed`);
  assert.ok(trap < install, `${name}: removal must be armed before the pack is installed, not after`);
}

// The library itself: removal is verified, not assumed, and a repeat run does not trust the last one.
const lib = read("nono-pack.sh");
assert.match(lib, /nono remove "\$NONO_PACK_PROFILE"/, "restore must actually run nono's removal command");
assert.match(lib, /diff "\$NONO_PACK_BEFORE" "\$after"/, "restore must compare against the before-snapshot");
assert.match(lib, /did not restore local agent configuration[\s\S]*?exit 1/, "an unrestored machine must fail the run");
assert.match(
  lib,
  /nono remove "\$profile" >\/dev\/null 2>&1 \|\| true\n\s*nono pull "\$profile"/,
  "install must remove first — neither pack installation nor the previous run's cleanup is assumed",
);

// The warning has to name the mutation and the dry-run trap, or it is not a warning.
assert.match(lib, /--dry-run skips/, "the warning must say dry-run does not skip installation");
assert.match(lib, /NONO_PACK_ACK/, "a developer machine must opt in before anything is installed");
assert.match(
  lib,
  /if \[ "\$\{CI:-\}" != "true" \] && \[ "\$\{NONO_PACK_ACK:-\}" != "1" \]; then\n\s*echo "::error/,
  "off CI, an unacknowledged run must refuse to install rather than warn and continue",
);

// The codex-nono row's confinement must be the vendor's alone: `nono run --profile <id> --`, no
// flags of ours. A narrowing added here would make the row measure our configuration instead.
const codex = read("run-probe-via-codex-stub.sh");
const invocation = codex.match(/NONO=\(nono run [^)]*\)/);
assert.ok(invocation, "expected the codex-nono launcher to build a `nono run` invocation");
assert.equal(
  invocation[0],
  'NONO=(nono run --profile "$CODEX_NONO_PROFILE" --)',
  "codex-nono must pass nono nothing but the profile — any other flag is a restriction this project invented",
);

// Ordering is only half of it — the removal has to actually notice residue. That runs against a
// throwaway $HOME and a stub `nono`, so it belongs in the same per-push suite; it is here so
// `node --test` is still the one entry point.
if (process.platform !== "win32") {
  execFileSync(path.join(scripts, "..", "tests", "nono-pack-restore.sh"), { stdio: "inherit" });
}

console.log("ok - every nono pack install is warned about, snapshotted, and reversed under a verified trap");
