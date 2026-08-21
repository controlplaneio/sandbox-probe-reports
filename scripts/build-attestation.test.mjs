// The attestation view renders a checked-in document, so the checked-in document
// is what has to be right: these guard that it is current, that it carries
// everything the view claims to show, and that it never reaches the matrix.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildAttestation } from "./build-attestation.mjs";

const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
const published = JSON.parse(read("../site/attestation.json"));

test("the published attestation is what the checked-in documents produce", () => {
  // Regenerate with: node scripts/build-attestation.mjs
  assert.deepEqual(published, buildAttestation());
});

test("the published attestation carries what the view shows", () => {
  assert.ok(published.profile.id && published.profile.version);
  assert.equal(typeof published.coverage.attestedFraction, "number");
  assert.ok(published.modifiers.socketMediation);
  assert.deepEqual(published.caveats.map((c) => c.id), ["runtime-capability-elevation"]);
  for (const v of published.verdicts) assert.ok(v.id && v.category && v.class);
});

test("gaps are structurally separate from the declared-side verdicts", () => {
  assert.ok(published.gaps.length > 0);
  assert.ok(published.gaps.every((g) => g.class === "gap"));
  assert.ok(!published.verdicts.some((v) => v.class === "gap"));
});

test("no drift data reaches the exposure matrix", () => {
  assert.ok(!read("../site/app.js").includes("attestation"));
});
