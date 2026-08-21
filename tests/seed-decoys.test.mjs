// Ticket #45: seed-decoys.sh is the one invocation point the matrix, the smoke job and
// attest-profile.sh call — planting with no flag, removing with --cleanup. It plants `file`
// decoys itself and delegates every other kind (socket, process, Windows named pipe) to the
// probe's own seed/cleanup, so this exercises the *dispatch* against a stub probe that mimics
// the real interface: `list-targets` JSON, "seed: planted N, skipped M", "cleanup: removed N".
//
// The stub is why this is runnable at all — the pinned probe (v1.1.0) predates seed/cleanup —
// and it is also what keeps the test safe: every path comes from the stub's registry, so
// nothing is ever planted at a real catalogue path on the machine running the tests.
// Run: node --test tests/seed-decoys.test.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "seed-decoys.sh");
const DECOY = "sandbox-probe decoy — not a real secret. Safe to delete.\n";

// A stub probe with the real one's three surfaces. It appends each subcommand it was asked for
// to $STUB_LOG, so "did the script delegate the other kinds?" is a fact, not an inference.
const STUB = `#!/usr/bin/env bash
echo "$1" >> "$STUB_LOG"
case "$1" in
  list-targets) [ -n "\${REGISTRY_FAILS:-}" ] && exit 1; cat "$REGISTRY" ;;
  seed)         echo "\${SEED_LINE:-seed: planted 3, skipped 1}" ;;
  cleanup)      echo "\${CLEANUP_LINE:-cleanup: removed 2 seeded artifact(s)}" ;;
esac
`;

// Each case owns a scratch dir; registry paths are built inside it.
function scratch(targets) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "seed-decoys-test-"));
  const probe = path.join(dir, "stub-probe");
  fs.writeFileSync(probe, STUB, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, "registry.json"), JSON.stringify(targets(dir)));
  return { dir, probe, log: path.join(dir, "log") };
}

function run(s, args, env = {}) {
  return execFileSync(SCRIPT, [...args, s.probe], {
    encoding: "utf8",
    env: { ...process.env, REGISTRY: path.join(s.dir, "registry.json"), STUB_LOG: s.log, ...env },
  });
}

const subcommands = (s) => fs.readFileSync(s.log, "utf8").trim().split("\n");

test("seed plants file decoys, leaves everything else to the probe, and sums both", () => {
  const s = scratch((dir) => [
    { path: path.join(dir, "home", ".aws", "credentials"), kind: "file", seedable: true },
    { path: path.join(dir, "taken"), kind: "file", seedable: true },
    { path: path.join(dir, "docker.sock"), kind: "socket", seedable: true },
    { path: path.join(dir, "not-seedable"), kind: "file", seedable: false },
  ]);
  fs.writeFileSync(path.join(s.dir, "taken"), "a real secret\n");

  const out = run(s, []);

  assert.equal(fs.readFileSync(path.join(s.dir, "home", ".aws", "credentials"), "utf8"), DECOY);
  assert.equal(fs.readFileSync(path.join(s.dir, "taken"), "utf8"), "a real secret\n", "soft: never clobbers");
  // The drift guard: bash must not write a regular file over a socket/pipe/process target, or it
  // would shadow the decoy the probe's own seed plants there.
  assert.equal(fs.existsSync(path.join(s.dir, "docker.sock")), false);
  assert.equal(fs.existsSync(path.join(s.dir, "not-seedable")), false);
  assert.deepEqual(subcommands(s), ["list-targets", "seed"]);
  // 1 file + the probe's 3; 1 already present + the probe's 1.
  assert.match(out, /planted 4, skipped 2/);
});

test("windows registry paths (backslashes) are planted, not turned into one odd filename", () => {
  const s = scratch((dir) => [{ path: `${dir}\\Users\\runneradmin\\.aws\\credentials`, kind: "file", seedable: true }]);
  run(s, []);
  assert.equal(fs.readFileSync(path.join(s.dir, "Users", "runneradmin", ".aws", "credentials"), "utf8"), DECOY);
});

test("cleanup removes the probe's artifacts and only files that are still decoys", () => {
  const s = scratch((dir) => [
    { path: path.join(dir, "decoy"), kind: "file", seedable: true },
    { path: path.join(dir, "real"), kind: "file", seedable: true },
    { path: path.join(dir, "gone"), kind: "file", seedable: true },
  ]);
  fs.writeFileSync(path.join(s.dir, "decoy"), DECOY);
  fs.writeFileSync(path.join(s.dir, "real"), "a real secret\n");

  const out = run(s, ["--cleanup"]);

  assert.equal(fs.existsSync(path.join(s.dir, "decoy")), false);
  assert.equal(fs.readFileSync(path.join(s.dir, "real"), "utf8"), "a real secret\n");
  assert.deepEqual(subcommands(s), ["cleanup", "list-targets"], "probe first: it needs no registry");
  assert.match(out, /removed 3 decoy artifact\(s\)/); // the probe's 2 + the one decoy file
});

test("an unreadable or empty registry is fatal in both modes, never a silent zero", () => {
  for (const args of [[], ["--cleanup"]]) {
    const empty = scratch(() => []);
    assert.throws(() => run(empty, args), /returned no seedable targets/);

    const broken = scratch((dir) => [{ path: path.join(dir, "x"), kind: "file", seedable: true }]);
    assert.throws(() => run(broken, args, { REGISTRY_FAILS: "1" }));
  }
});

test("a probe summary the script cannot read is fatal, not counted as zero", () => {
  const s = scratch((dir) => [{ path: path.join(dir, "x"), kind: "file", seedable: true }]);
  assert.throws(() => run(s, [], { SEED_LINE: "seeded some things" }), /unrecognised summary/);
  assert.throws(() => run(s, ["--cleanup"], { CLEANUP_LINE: "all done" }), /unrecognised summary/);
});
