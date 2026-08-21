// Ticket #43: record which harnesses' Host mounts cell moves under the corrected
// mount enumerator (sandbox-probe spec #7).
//
// Takes two all-reports.json manifests — one produced with the probe as pinned
// before the fix, one after — and reports, per harness identity, whether the
// Host mounts cell changed state, which mount is responsible, and whether any
// other capability category moved (it must not: the fix corrects one category's
// inputs, nothing else).
//
// Usage: node scripts/mount-cell-moves.mjs <before.json> <after.json>
// Exits non-zero if a category other than Host mounts changed state.
//
// Cell states, the category set and the exposure scale are NOT redefined here:
// this loads site/app.js and uses its own build()/cellStates(), so the record
// says exactly what the site says. Same loader the site tests use.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

export function loadSiteModel() {
  const appJs = fs.readFileSync(path.join(here, "..", "site", "app.js"), "utf8");
  const pure = appJs.split("// ── boot")[0];
  const loader = new Function(
    "module",
    "document",
    "getComputedStyle",
    `${pure}\nmodule.exports = { build, CATEGORIES, mountKey, mountLabel };`
  );
  const mod = { exports: {} };
  loader(mod, { documentElement: {} }, () => ({ getPropertyValue: () => "" }));
  return mod.exports;
}

const { build, CATEGORIES, mountKey, mountLabel } = loadSiteModel();
// An unmapped finding type lands in the site's uncounted "Other" column; a
// value-format change must not conjure one, so it is compared like the rest.
const COLUMNS = [...CATEGORIES, { key: "other", label: "Other" }];

const mountsOf = (row) =>
  (row?.report?.findings || [])
    .filter((f) => f.findingType === "mounted_volumes_detections")
    .flatMap((f) => (Array.isArray(f.value) ? f.value : f.value == null ? [] : [f.value]));

// one point per identity: the newest, which is the run being recorded.
const latest = (rows) =>
  Object.fromEntries(Object.entries(build(rows)).map(([id, pts]) => [id, pts.at(-1)]));

// The mount responsible for a move: reported by the sandbox after the fix, and
// neither shared with its baseline (which would cancel out) nor already seen
// before the fix.
function responsibleMounts(beforePt, afterPt) {
  const seen = new Set([
    ...mountsOf(afterPt.baselineRow).map(mountKey),
    ...mountsOf(beforePt.row).map(mountKey),
  ]);
  return mountsOf(afterPt.row).filter((m) => !seen.has(mountKey(m))).map(mountLabel);
}

export function compare(beforeRows, afterRows) {
  const before = latest(beforeRows);
  const after = latest(afterRows);
  const moved = [];
  const unchanged = [];
  const otherMoved = [];
  for (const id of Object.keys(after).sort()) {
    if (!before[id]) continue; // identity absent before the fix — nothing to compare
    const b = before[id].states;
    const a = after[id].states;
    for (const { key, label } of COLUMNS) {
      const from = b[key] ?? "na";
      const to = a[key] ?? "na";
      if (from === to) continue;
      if (key === "host_mounts") moved.push({ id, from, to, mounts: responsibleMounts(before[id], after[id]) });
      else otherMoved.push({ id, category: label, from, to });
    }
    if ((b.host_mounts ?? "na") === (a.host_mounts ?? "na")) unchanged.push({ id, state: a.host_mounts ?? "na" });
  }
  return { moved, unchanged, otherMoved };
}

export function renderMarkdown({ moved, unchanged, otherMoved }) {
  const out = [];
  out.push("### Host mounts cells that moved\n");
  if (!moved.length) out.push("_None._\n");
  else {
    out.push("| Harness identity | Before | After | Mount responsible |");
    out.push("| --- | --- | --- | --- |");
    for (const m of moved) out.push(`| \`${m.id}\` | ${m.from} | ${m.to} | ${m.mounts.join(", ") || "_not identified_"} |`);
    out.push("");
  }
  out.push("### Host mounts cells confirmed unchanged\n");
  out.push(unchanged.length ? unchanged.map((u) => `- \`${u.id}\` — ${u.state}`).join("\n") + "\n" : "_None._\n");
  out.push("### Other capability categories that moved (must be empty)\n");
  out.push(
    otherMoved.length
      ? otherMoved.map((o) => `- \`${o.id}\` — ${o.category}: ${o.from} → ${o.to}`).join("\n") + "\n"
      : "_None._\n"
  );
  return out.join("\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [beforeFile, afterFile] = process.argv.slice(2);
  if (!beforeFile || !afterFile) {
    console.error("usage: mount-cell-moves.mjs <before.json> <after.json>");
    process.exit(1);
  }
  const read = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
  const result = compare(read(beforeFile), read(afterFile));
  process.stdout.write(renderMarkdown(result));
  if (result.otherMoved.length) {
    console.error(`mount-cell-moves: ${result.otherMoved.length} non-Host-mounts state change(s) — the fix should not move these`);
    process.exit(1);
  }
}
