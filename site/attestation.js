// The attestation view: declared-versus-actual, its own page on purpose. The
// exposure matrix (app.js) is baseline-versus-sandbox and never sees this data,
// so no drift class can reach the 0–8 exposure count. Renders attestation.json,
// which is built from checked-in documents (scripts/build-attestation.mjs), so
// the verdict can be read without nono and without running a scan.
"use strict";

const CLASSES = ["match", "overclaim", "unprovable", "unattested"];
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const pct = (f) => `${Math.round(f * 100)}%`;
// A gap names itself by whichever field its finding type carries.
const gapSubject = (g) => g.path ?? g.host ?? g.envKey;

function renderMeta(a) {
  const c = a.coverage;
  const bits = [
    `<code>${esc(a.profile.id)}</code> version <b>${esc(a.profile.version)}</b>` +
      (a.profile.manifestVersion ? ` · manifest ${esc(a.profile.manifestVersion)}` : ""),
    `coverage <b>${pct(c.attestedFraction)}</b> of the declared surface (${c.attested}/${c.declared} declared units attested)`,
  ];
  // Modifiers change how results are read; caveats say the reading may be
  // incomplete. Both belong here so nobody has to open the profile.
  if (a.modifiers?.socketMediation !== "pathname")
    bits.push(`<span class="tag mod">socket mediation ${esc(a.modifiers?.socketMediation ?? "off")}</span> — socket grants are not enforced, so no socket result reads as policy`);
  for (const cv of a.caveats ?? [])
    bits.push(`<span class="tag caveat">caveat: ${esc(cv.id)}</span> — ${esc(cv.reason)}`);
  if (a.source) bits.push(`<span class="muted">source: ${esc(a.source)}</span>`);
  document.getElementById("meta").innerHTML = bits.map((b) => `<div>${b}</div>`).join("");
}

function renderGaps(gaps) {
  document.getElementById("gaps").innerHTML = gaps.length
    ? "<ul class='gap-list'>" + gaps.map((g) =>
        `<li><span class="badge gap">gap</span> <code>${esc(gapSubject(g))}</code>
         <span class="muted">${esc(g.findingType)}</span></li>`).join("") + "</ul>"
    : "<p class='muted'>No gaps: nothing reachable that the profile does not declare.</p>";
}

function renderVerdicts(verdicts) {
  let h = "<table><thead><tr><th>declared unit</th><th>category</th><th>class</th><th>note</th></tr></thead><tbody>";
  for (const cls of CLASSES) {
    for (const v of verdicts.filter((x) => x.class === cls)) {
      h += `<tr><td class="id">${esc(v.id)}</td><td>${esc(v.category)}</td>` +
        `<td class="drift ${cls}">${cls}</td>` +
        `<td class="note">${esc(v.reason ?? "")}${v.modifier ? ` <span class="tag mod">${esc(v.modifier)}</span>` : ""}</td></tr>`;
    }
  }
  document.getElementById("verdicts").innerHTML = h + "</tbody></table>";
}

function renderUnmediated(items) {
  if (!items?.length) return;
  document.getElementById("unmediated-section").classList.remove("hidden");
  document.getElementById("unmediated").innerHTML =
    "<ul class='gap-list'>" + items.map((u) =>
      `<li><span class="badge unattested">unattested</span> <code>${esc(u.path)}</code>
       <span class="muted">${esc(u.reason)}</span></li>`).join("") + "</ul>";
}

async function boot() {
  let a;
  try { const res = await fetch("attestation.json"); if (res.ok) a = await res.json(); } catch { /* below */ }
  if (!a) { document.getElementById("verdicts").textContent = "No attestation data."; return; }
  renderMeta(a);
  renderGaps(a.gaps ?? []);
  renderVerdicts(a.verdicts ?? []);
  renderUnmediated(a.unmediated);
}
boot();
