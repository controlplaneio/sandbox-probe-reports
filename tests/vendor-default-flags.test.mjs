// Ticket #33: the sandbox rows must measure the vendor's default posture, so every flag the
// launcher passes to a runtime has to be declared here with a reason from a fixed vocabulary.
// Five separate audits each found a narrowing this repo had invented; this is the guard that
// makes the sixth fail in the pull request instead. It parses the launcher itself, so a flag
// that is added, changed or removed there without updating the declaration fails too.
// Contributor guidance: README, "Adding a sandbox row".
// Run: node tests/vendor-default-flags.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The whole vocabulary. Anything else — "seemed sensible", "safer", "matches the other rows" —
// is not a reason, and a flag that needs one of those is a narrowing this project invented.
const REASONS = ["vendor-default", "minimum-to-run", "output-only"];

// Every flag the launcher passes, and why. A flag needed only to get the report out of the
// sandbox is minimum-to-run: without it the tool starts but the probe cannot emit its report.
const DECLARED = {
  srt: { "--settings": "minimum-to-run" }, // deny-by-default policy, widened only to write the report
  firejail: { "--quiet": "output-only" }, // quiets firejail's banner, no effect on the boundary
  nono: {
    "--silent": "output-only",
    "--allow-cwd": "minimum-to-run", // nono denies everything with zero flags and will not start
    "--allow": "minimum-to-run", // the report directory, so the probe can write its output
  },
};

// Returns a list of problems; empty means every flag that actually runs carries a declared reason.
function audit(source, declared) {
  const problems = [];
  const vocabulary = `accepted reasons: ${REASONS.join(", ")}`;

  for (const [runtime, flags] of Object.entries(declared)) {
    for (const [flag, reason] of Object.entries(flags)) {
      if (!REASONS.includes(reason)) {
        problems.push(`${runtime} declares ${flag} with reason "${reason}" — ${vocabulary}`);
      }
    }
  }

  // The lines that actually launch the probe are the source of truth for what gets passed.
  const invocations = source
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#") && line.includes('"${CMD[@]}"'));

  const launched = new Set();
  for (const line of invocations) {
    const runtime = line.trim().split(/\s+/)[0];
    launched.add(runtime);
    const flags = declared[runtime];
    if (!flags) {
      problems.push(`${runtime} is launched but declares no flags — every flag needs a reason, ${vocabulary}`);
      continue;
    }
    const passed = line.match(/--[a-z0-9-]+(?:=[^\s"']*)?/g) ?? []; // --net=none names itself in full
    for (const token of new Set(passed)) {
      if (!(token.split("=")[0] in flags)) problems.push(`${runtime} passes undeclared flag ${token} — ${vocabulary}`);
    }
    const names = new Set(passed.map((token) => token.split("=")[0]));
    for (const flag of Object.keys(flags)) {
      if (!names.has(flag)) {
        problems.push(`${runtime} declares ${flag} but the launcher no longer passes it — ${vocabulary}`);
      }
    }
  }

  for (const runtime of Object.keys(declared)) {
    if (!launched.has(runtime)) problems.push(`${runtime} is declared but the launcher never launches it`);
  }
  return problems;
}

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "run-probe-in-sandbox.sh");
const source = fs.readFileSync(script, "utf8");

// -- what actually runs today --
assert.deepEqual(audit(source, DECLARED), [], "the launcher passes a flag with no declared reason");

// -- a narrowing this project invented, network or filesystem, fails and names runtime + flag --
const narrowings = [
  ['firejail --quiet "${CMD[@]}"', 'firejail --quiet --net=none "${CMD[@]}"', /firejail passes undeclared flag --net=none/],
  ['srt --settings "$SETTINGS"', 'srt --settings "$SETTINGS" --read-only', /srt passes undeclared flag --read-only/],
];
for (const [from, to, expected] of narrowings) {
  const problems = audit(source.replace(from, to), DECLARED);
  assert.equal(problems.length, 1, `expected exactly one problem, got: ${problems.join("; ")}`);
  assert.match(problems[0], expected);
  assert.match(problems[0], /accepted reasons: vendor-default, minimum-to-run, output-only/);
}

// -- a reason outside the vocabulary is not a reason --
assert.match(
  audit(source, { ...DECLARED, firejail: { "--quiet": "seemed-sensible" } }).join("\n"),
  /firejail declares --quiet with reason "seemed-sensible" — accepted reasons: vendor-default, minimum-to-run, output-only/,
);

// -- the declaration cannot drift from the launcher: changing or removing a flag fails --
assert.match(
  audit(source.replace("firejail --quiet", "firejail"), DECLARED).join("\n"),
  /firejail declares --quiet but the launcher no longer passes it/,
);
assert.match(
  audit(source.replace("firejail --quiet", "firejail --noprofile"), DECLARED).join("\n"),
  /firejail passes undeclared flag --noprofile[\s\S]*firejail declares --quiet but the launcher no longer passes it/,
);

// -- a runtime added to the launcher must declare its flags before it can run --
assert.match(
  audit(source.replace("  nono)", '  bwrap)\n    bwrap --unshare-all "${CMD[@]}"\n    ;;\n  nono)'), DECLARED).join("\n"),
  /bwrap is launched but declares no flags/,
);

console.log("ok - every flag the sandbox launcher passes carries a declared reason");
