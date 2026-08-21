// Ticket #44: keep the mounts drill-down readable as entry counts grow.
// Mounts present in both baseline and sandbox collapse/de-emphasise; mounts
// unique to the sandbox show first. Old (plain-string) and new
// (object-with-mount-root) mount value formats must both render without error.
// Run: node tests/site/mount-drilldown.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appJs = fs.readFileSync(path.join(here, "..", "..", "site", "app.js"), "utf8");

const pure = appJs.split("// ── boot")[0];
const loader = new Function(
  "module",
  "document",
  "getComputedStyle",
  `${pure}\nmodule.exports = { mountKey, mountLabel, renderMountDrill, findingItems };`
);
const mod = { exports: {} };
loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
const { mountKey, mountLabel, renderMountDrill, findingItems } = mod.exports;

function row(value) {
  return { report: { findings: [{ findingType: "mounted_volumes_detections", value }] } };
}
const FTS = ["mounted_volumes_detections"];

// -- old format: plain path strings --
{
  const baseline = row(["/", "/home"]);
  const sandbox = row(["/", "/home", "/mnt/host-decoy"]);
  const items = findingItems(sandbox, FTS);
  const html = renderMountDrill(items, baseline, FTS);
  // unique entry appears, and appears before the collapsed common group
  const uniqueIdx = html.indexOf("/mnt/host-decoy");
  const commonIdx = html.indexOf("Also in baseline");
  assert.ok(uniqueIdx > -1, "unique mount rendered");
  assert.ok(commonIdx > uniqueIdx, "unique-to-sandbox group precedes the collapsed baseline-shared group");
  assert.ok(html.includes("<details"), "shared-with-baseline mounts are collapsed behind <details>");
  assert.ok(html.includes("/") && html.includes("/home"), "shared mounts still rendered, just de-emphasised");
}

// -- new format: object with source/target/mountRoot --
{
  const baseline = row([{ source: "/dev/sda1", target: "/", fsType: "ext4", mountRoot: "/" }]);
  const sandbox = row([
    { source: "/dev/sda1", target: "/", fsType: "ext4", mountRoot: "/" },
    { source: "/dev/sda1", target: "/host-etc", fsType: "ext4", mountRoot: "/etc" },
  ]);
  const items = findingItems(sandbox, FTS);
  assert.doesNotThrow(() => renderMountDrill(items, baseline, FTS), "object-shaped mounts render without error");
  const html = renderMountDrill(items, baseline, FTS);
  assert.ok(html.includes("/host-etc"), "new-format unique mount displays its target");
  assert.ok(html.includes("Also in baseline"), "new-format shared mount collapses too");
}

// -- mixed old/new formats side by side (historical + current reports) --
{
  const baseline = row(["/"]);
  const sandbox = row([{ source: "/dev/sda1", target: "/host-etc", mountRoot: "/etc" }]);
  assert.doesNotThrow(() => renderMountDrill(findingItems(sandbox, FTS), baseline, FTS));
}

// -- no baseline (unprovable) doesn't throw --
{
  const sandbox = row(["/", "/mnt/x"]);
  assert.doesNotThrow(() => renderMountDrill(findingItems(sandbox, FTS), undefined, FTS));
}

// -- mountKey treats equivalent old-format strings as identical, new-format
//    objects compared on their fields, not object identity --
assert.equal(mountKey("/home"), mountKey("/home"));
assert.equal(mountKey({ source: "/a", target: "/b" }), mountKey({ source: "/a", target: "/b" }));
assert.notEqual(mountKey({ source: "/a", target: "/b" }), mountKey({ source: "/a", target: "/c" }));
assert.equal(mountLabel("/home"), "/home");
assert.equal(mountLabel({ target: "/host-etc", source: "/dev/sda1" }), "/host-etc");

console.log("ok - mount drill-down leads with sandbox-unique entries and collapses shared ones, old/new formats both safe");
