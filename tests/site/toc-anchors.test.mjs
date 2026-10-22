// Pins the on-page table of contents against link rot: every anchor in the ToC
// must point at an id that actually exists in index.html, and all four sections
// must be listed. A string-level check on the file, like the other static checks
// in this suite — the ToC is hand-written markup, so nothing else would catch a
// renamed section id.
// Run: node --test tests/site/toc-anchors.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "..", "..", "site", "index.html"), "utf8");

// the ToC is one <nav id="toc"> block; scope the anchor sweep to it so the
// tagline's cross-page link to attestation.html is not mistaken for a ToC entry.
const toc = html.match(/<nav id="toc"[\s\S]*?<\/nav>/)?.[0];
const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
const anchors = toc ? [...toc.matchAll(/href="#([^"]+)"/g)].map((m) => m[1]) : [];

test("index.html carries a ToC nav", () => {
  assert.ok(toc, "index.html must contain a <nav id=\"toc\"> block");
  assert.ok(anchors.length >= 4, `the ToC must link at least 4 sections (found ${anchors.length})`);
});

test("every ToC anchor target exists in index.html", () => {
  // guard: with no anchors the loop below is vacuous, so assert there are some
  // before asserting anything about them.
  assert.ok(anchors.length >= 4, `expected at least 4 ToC anchors to check (found ${anchors.length})`);
  for (const a of anchors)
    assert.ok(ids.has(a), `ToC links to #${a} but no element in index.html has id="${a}"`);
});

test("the ToC lists all four sections", () => {
  for (const want of ["latest-section", "matrix-section", "charts-section", "flips-section"])
    assert.ok(anchors.includes(want), `the ToC must link to #${want}`);
});

test("the ToC names the sections it links", () => {
  for (const label of ["Latest changes", "Comparison", "Over time", "Changes"])
    assert.ok(toc.includes(label), `the ToC must be labelled "${label}"`);
});

test("the new Latest changes section exists with its own render target", () => {
  assert.ok(/<section id="latest-section"/.test(html), "a #latest-section section must exist");
  assert.ok(ids.has("latest"), "the Latest changes section needs a #latest render target");
  assert.ok(html.indexOf('id="latest-section"') < html.indexOf('id="matrix-section"'),
    "Latest changes must sit above Comparison");
  assert.ok(html.indexOf('id="flips-section"') > html.indexOf('id="charts-section"'),
    "the full Changes section must stay at the bottom");
});
