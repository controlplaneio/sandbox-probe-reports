// The nesting verdicts have to be followable from the main line alone. Every
// research ticket whose long-form write-up lives on an unmerged `research/*`
// branch must have its finding landed in the evidence index, and the documents
// that carry the reasoning must not link to anything that isn't here.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(resolve(repo, p), "utf8");

const evidence = read("docs/nesting-evidence.md");
const tickets = "/.scratch/sandbox-canary-nesting/issues";

test("every branch-backed research verdict is landed in the evidence index", () => {
  const branchBacked = readdirSync(repo + tickets).filter((f) =>
    /on branch\s+`?research\//s.test(read(tickets.slice(1) + "/" + f)),
  );
  assert.ok(branchBacked.length >= 10, "expected the research tickets to be present");
  for (const ticket of branchBacked) {
    assert.ok(
      evidence.includes(ticket),
      `${ticket} cites an unmerged research branch but docs/nesting-evidence.md does not carry its finding`,
    );
  }
});

test("the landed reasoning links only to things that are here", () => {
  for (const doc of [
    "docs/nesting-evidence.md",
    "docs/adr/0003-canary-nesting-and-the-comparability-criterion.md",
  ]) {
    for (const [, link] of read(doc).matchAll(/\]\((?!https?:|#)([^)]+)\)/g)) {
      const target = resolve(repo, dirname(doc), link.split("#")[0]);
      assert.ok(existsSync(target), `${doc} links to a missing ${link}`);
    }
  }
});
