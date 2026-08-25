// sandbox-probe reporting page. All derivation is client-side from one concatenated
// file (see ADR 0001 / docs/reporting-site-plan.md). Falls back to sample-data.json
// for local dev until the CI aggregate job produces all-reports.json.
"use strict";

const CATEGORIES = [
  { key: "fs_read", label: "FS read" },
  { key: "fs_write", label: "FS write" },
  { key: "net_egress", label: "Net egress" },
  { key: "local_services", label: "Local svc" },
  { key: "ipc_sockets", label: "IPC sockets" },
  { key: "process_visibility", label: "Proc vis" },
  { key: "host_mounts", label: "Mounts" },
  { key: "privileged", label: "Privileged" },
];
const FT2CAT = {
  sensitive_readable_paths: "fs_read",
  writeable_paths: "fs_write",
  external_host_dns_resolution: "net_egress",
  external_host_connectivity: "net_egress",
  tcp_ports_open: "local_services",
  udp_ports_open: "local_services",
  unix_socket_detection: "ipc_sockets",
  named_pipe_detection: "ipc_sockets",
  process_detection: "process_visibility",
  parent_process_detection: "process_visibility",
  mounted_volumes_detections: "host_mounts",
};
// context-only finding types (not counted); everything else unmapped -> "other" column.
const CONTEXT_FT = new Set([
  "sandbox_detection", "user_context_detection", "hostname_detection",
  "environment_detection", "proxy_detection", "env_secret_detection",
  // local_listeners is the kernel's socket table — what is BOUND in this
  // namespace, not what this process can reach. The two diverge under exactly
  // the sandboxes worth measuring: a Seatbelt profile that denies network
  // leaves the table byte-identical while connect() returns EPERM. Scoring it
  // as a capability would therefore mark every correctly-confined macOS and
  // Windows row leaked, permanently. It is context, which is why the probe
  // reports the inventory and the reachability as separate findings.
  "local_listeners",
  // local_probe_status says how that measurement went — which table was read,
  // whether the UDP feedback channel is live, the namespace, and the per-port
  // outcomes. It carries no capability of its own.
  "local_probe_status",
]);

// sandbox_detection carries two kinds of claim (CONTEXT.md, "Enforcement badge vs
// mechanism"): the wrapper name — an inference — and kernel-attested mechanisms,
// emitted as sibling findings. Both are context signals: neither is a capability
// category, so neither moves the 0–8 exposure count.
const MECHANISMS = new Set([
  "user-namespace", "landlock", "seccomp-filter", "seccomp-notify", "seccomp-strict", "no-new-privs",
  // Windows, read off the process token with IsTokenRestricted(), so kernel-attested like the
  // rest. It must be in this set: sandboxOf() takes the first value that is NOT a mechanism as
  // the wrapper badge, so leaving it out would render it as a tool name the probe cannot
  // identify — a restricted token says nothing about which sandbox built it.
  "restricted-token",
  // Windows, read off the process token with TokenIsAppContainer. The primitive behind MXC's
  // ProcessContainer backend, which is GitHub Copilot CLI's Windows sandbox. Same argument as
  // above: an AppContainer token cannot say who built it — Store apps, Chromium's renderer and
  // Defender Application Guard all produce one — so it is a mechanism, never the badge.
  "app-container",
]);

const find = (r, ft) => r.report.findings.find((f) => f.findingType === ft);
// snake_case: the probe emits "kernel_release" (pkg/tasks/baseline.go). This read was
// camelCase and so returned "?" for every report ever published, which silently reduced
// the fingerprint to harnessVersion|os and made "harness X→Y" the only cause a flip
// could ever be attributed to.
const kernelOf = (r) => (find(r, "environment_detection")?.value?.kernel_release) || "?";
const sandboxValues = (r) =>
  r.report.findings.filter((f) => f.findingType === "sandbox_detection")
    .map((f) => f.value).filter((v) => typeof v === "string" && v !== "");
// the badge is the wrapper name; a run that only proves mechanisms has no badge.
const sandboxOf = (r) => sandboxValues(r).find((v) => !MECHANISMS.has(v)) || "none";
const mechanismsOf = (r) => sandboxValues(r).filter((v) => MECHANISMS.has(v));
const isRoot = (r) => (find(r, "user_context_detection")?.value?.euid) === 0;
function harnessVersion(r) {
  const skip = new Set(["os", "harness", "sandbox", "runner", "mode"]);
  for (const t of r.report.metadata?.tags || []) {
    const [k, v] = t.split("=");
    if (!skip.has(k) && v) return v;
  }
  return "";
}
// The matrix builds the probe with plain `go build`, so ldflags never run and .commit is
// the literal string "unknown" in every published report. binaryVersion is populated from
// runtime/debug.ReadBuildInfo, which does carry the real module version. Prefer it.
const probeOf = (r) => r.report.probeBinary?.binaryVersion || r.report.probeBinary?.commit || "unknown";
const fingerprint = (r) => [harnessVersion(r), probeOf(r), kernelOf(r), r.os].join("|");

// Mount entries come in two shapes: a plain path string (pre spec-7 probe), or
// an object carrying source/target/fsType and the mount root (post spec-7
// probe, ADR-0002's neighbour ticket #7 in sandbox-probe). Both must render
// without error, so drill-down display/comparison goes through these two
// normalizers rather than assuming either shape.
function mountLabel(v) {
  if (v == null || typeof v !== "object") return String(v);
  return v.target || v.source || v.path || JSON.stringify(v);
}
function mountKey(v) {
  if (v == null || typeof v !== "object") return String(v);
  return [v.source, v.target, v.mountRoot, v.fsType].filter((x) => x != null).join("|") || JSON.stringify(v);
}

// A finding only signals a real capability if it carries something: a task can
// run and find nothing, emitting the finding type with an empty value (e.g. DNS
// resolution blocked -> external_host_dns_resolution: []). Empty != leaked.
function hasSignal(f) {
  const v = f.value;
  if (Array.isArray(v)) return v.length > 0;
  if (v && typeof v === "object") return Object.keys(v).length > 0;
  return v != null && v !== "";
}

// which leak categories a report exhibits (a non-empty finding of that type).
function leakedCats(r) {
  const s = new Set();
  for (const f of r.report.findings) {
    if (!hasSignal(f)) continue;
    const cat = FT2CAT[f.findingType];
    if (cat) s.add(cat);
    else if (!CONTEXT_FT.has(f.findingType)) s.add("other");
  }
  return s;
}

// Which categories this report actually MEASURED — at least one of their finding types is
// present, whatever its value. Absent is not the same as empty, and conflating them is
// what made a failed scan render as a security improvement: a task that never ran emits
// no finding, leakedCats() then sees no leak, and the cell scored "blocked".
//
// Empty still counts as measured. `writeable_paths: []` is a task that ran and found
// nothing, which is a real negative and the whole point of the baseline comparison.
function measuredCats(r) {
  const s = new Set();
  for (const f of r.report.findings) {
    const cat = FT2CAT[f.findingType];
    if (cat) s.add(cat);
  }
  return s;
}

// state per category for one harness row, normalized against its same-run same-os baseline.
//
// Three things have to be true before a cell can say "blocked", and each has its own
// failure state, because collapsing them is how an unmeasured cell became a security
// claim:
//   1. a baseline exists at all                     -> else unprovable
//   2. the baseline measured this category          -> else unprovable (achievability
//      cannot be established from a scan that never ran)
//   3. this row measured it too                     -> else unprovable
// Only then does the baseline's result decide between "na" (the baseline could not do it
// either, so there is nothing to block) and the scored leaked/blocked pair.
function cellStates(row, baseline) {
  const leaks = leakedCats(row);
  const measured = measuredCats(row);
  const achievable = baseline ? leakedCats(baseline) : new Set();
  const baseMeasured = baseline ? measuredCats(baseline) : new Set();
  const out = {};
  for (const { key } of CATEGORIES) {
    if (key === "privileged") {
      // euid comes from user_context_detection; absent means unmeasured, not non-root.
      out[key] = find(row, "user_context_detection") === undefined
        ? "unprovable"
        : (isRoot(row) ? "leaked" : "blocked");
      continue;
    }
    if (!baseline) out[key] = "unprovable";
    else if (!baseMeasured.has(key)) out[key] = "unprovable";
    else if (!measured.has(key)) out[key] = "unprovable";
    else if (!achievable.has(key)) out[key] = "na";
    else out[key] = leaks.has(key) ? "leaked" : "blocked";
  }
  if (leaks.has("other")) out.other = "leaked";
  return out;
}

// ── build model: identities -> one ordered point per run ───────────────────────
function build(rows) {
  // index baselines by os|runTimestamp
  const baselines = {};
  for (const r of rows) if (r.harness === "direct") baselines[`${r.os}|${r.runTimestamp}`] = r;

  const byIdentity = {};
  for (const r of rows) {
    const id = `${r.os}/${r.harness}`;
    (byIdentity[id] ||= []).push(r);
  }

  // Retirement (spec #5 / #30): an identity whose most recent run predates its
  // OS's latest scan no longer receives runs, so it leaves the matrix and the
  // charts rather than showing a stale row or a line that stops mid-axis. Read-
  // time filter only — every historical report stays on the data branch. It is
  // arrival's inverse: a first-time identity is in the latest scan, so it joins
  // with no code change, and a departed one leaves the same way.
  const latestScan = {};
  for (const r of rows) if (r.runTimestamp > (latestScan[r.os] || "")) latestScan[r.os] = r.runTimestamp;

  const identities = {};
  for (const [id, list] of Object.entries(byIdentity)) {
    list.sort((a, b) => a.runTimestamp.localeCompare(b.runTimestamp));
    if (list.at(-1).runTimestamp < latestScan[list[0].os]) continue;
    // One point per run. This used to collapse runs sharing a fingerprint, keeping the
    // latest and discarding the rest — which threw away the disagreements that prove a
    // measurement is unstable. It cost real data: macos/claude-sandbox observed tcp
    // [49173] at 12:58 on 2026-08-21 and the 13:06 run overwrote it silently. Two runs
    // that disagree are a finding, not a duplicate.
    //
    // fingerprint() is still what flips() attributes a change to, so it stays; it is no
    // longer a deduplication key.
    const arr = list.map((r) => {
      const base = baselines[`${r.os}|${r.runTimestamp}`];
      return {
        fp: fingerprint(r), ts: r.runTimestamp, harnessVersion: harnessVersion(r),
        probe: probeOf(r), kernel: kernelOf(r), os: r.os,
        sandbox: sandboxOf(r), mechanisms: mechanismsOf(r), root: isRoot(r), row: r,
        states: cellStates(r, base), hasBaseline: !!base, baselineRow: base,
      };
    });
    for (const p of arr) p.exposure = CATEGORIES.filter((c) => p.states[c.key] === "leaked").length;
    identities[id] = arr;
  }
  return identities;
}

// ── flips ──────────────────────────────────────────────────────────────────────
function flips(identities) {
  const out = [];
  for (const [id, pts] of Object.entries(identities)) {
    if (id.endsWith("/direct")) continue;
    for (let i = 1; i < pts.length; i++) {
      const a = pts[i - 1], b = pts[i];
      const moved = [];
      if (a.harnessVersion !== b.harnessVersion) moved.push(`harness ${a.harnessVersion || "?"}→${b.harnessVersion || "?"}`);
      if (a.probe !== b.probe) moved.push(`probe ${a.probe}→${b.probe}`);
      if (a.kernel !== b.kernel) moved.push(`kernel ${a.kernel}→${b.kernel}`);
      const cause = moved.join(" · ") || "no config change";
      for (const c of CATEGORIES) {
        const s0 = a.states[c.key], s1 = b.states[c.key];
        if ((s0 === "leaked" || s0 === "blocked") && (s1 === "leaked" || s1 === "blocked") && s0 !== s1)
          out.push({ id, ts: b.ts, cat: c.label, from: s0, to: s1, cause, degraded: s1 === "leaked" });
      }
    }
  }
  return out.sort((a, b) => b.ts.localeCompare(a.ts));
}

// ── rendering ───────────────────────────────────────────────────────────────────
const GLYPH = { leaked: "●", blocked: "●", na: "—", unprovable: "?" };
let MODEL, OSFILTER = "";

// Chart colors follow the same CSS custom properties as the rest of the page
// (style.css), so the dark ControlPlane theme and the charts never drift apart.
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const CHART_TEXT = () => cssVar("--cp-text-muted");
const CHART_BORDER = () => cssVar("--cp-neutral-8");
const CHART_AXIS = {
  axisLabel: { color: CHART_TEXT() },
  axisLine: { lineStyle: { color: CHART_BORDER() } },
  splitLine: { lineStyle: { color: CHART_BORDER() } },
};

function renderMeta(rows) {
  const runs = new Set(rows.map((r) => r.runTimestamp));
  const harnesses = new Set(rows.map((r) => r.harness).filter((h) => h !== "direct"));
  document.getElementById("meta").textContent =
    `${rows.length} reports · ${harnesses.size} harnesses · ${runs.size} runs · ${[...runs].sort().at(-1)?.slice(0, 10)} latest`;
}

function renderMatrix() {
  const ids = Object.keys(MODEL).filter((id) => !OSFILTER || id.startsWith(OSFILTER + "/")).sort();
  let h = "<table><thead><tr><th>identity</th><th>enforcement</th>";
  for (const c of CATEGORIES) h += `<th>${c.label}</th>`;
  h += "<th>exp.</th></tr></thead><tbody>";
  for (const id of ids) {
    const pts = MODEL[id], p = pts.at(-1), prev = pts.length > 1 ? pts.at(-2) : null;
    const baseline = id.endsWith("/direct");
    h += `<tr class="${baseline ? "baseline-row" : ""}"><td class="id">${id}${baseline ? ' <span class="tag">baseline</span>' : ""}</td>`;
    const mech = p.mechanisms.map((m) => ` <span class="tag mech" title="kernel-attested mechanism">${m}</span>`).join("");
    h += `<td>${baseline ? "—" : `<span class="tag enf">${p.sandbox}</span>${mech}${p.root ? ' <span class="tag root">root</span>' : ""}`}</td>`;
    for (const c of CATEGORIES) {
      const st = p.states[c.key] || "na";
      const changed = prev && !baseline && prev.states[c.key] !== st && (st === "leaked" || st === "blocked");
      const arrow = changed ? (st === "leaked" ? '<span class="up">▲</span>' : '<span class="down">▼</span>') : "";
      h += `<td class="cell ${st}" data-id="${id}" data-cat="${c.key}" title="${st}">${GLYPH[st] || ""}${arrow}</td>`;
    }
    h += `<td class="exp">${baseline ? "—" : p.exposure}</td></tr>`;
  }
  h += "</tbody></table>";
  document.getElementById("matrix").innerHTML = h;
  document.querySelectorAll("#matrix .cell").forEach((td) =>
    td.addEventListener("click", () => drill(td.dataset.id, td.dataset.cat)));
}

function findingItems(row, fts) {
  const items = [];
  if (!row) return items;
  for (const ft of fts) {
    const f = find(row, ft);
    if (f) items.push(...(Array.isArray(f.value) ? f.value : [f.value]));
  }
  return items;
}

// host_mounts drill-down: entry counts grew a lot once the enumerator started
// reporting every mount root (spec #7), so the raw list leads with what the
// sandbox exposes beyond the baseline — mounts also reachable in the baseline
// are collapsed rather than deleted, since they're still real, just not new.
function renderMountDrill(items, baselineRow, fts) {
  if (!items.length) return `<p class="muted">No accessible items.</p>`;
  const baseKeys = new Set(findingItems(baselineRow, fts).map(mountKey));
  const unique = [], common = [];
  for (const it of items) (baseKeys.has(mountKey(it)) ? common : unique).push(it);
  const li = (v) => `<li>${mountLabel(v)}</li>`;
  let h = "";
  if (unique.length)
    h += `<p class="mount-group-label">Unique to this sandbox (${unique.length})</p><ul>${unique.map(li).join("")}</ul>`;
  if (common.length)
    h += `<details class="mount-common"><summary>Also in baseline (${common.length})</summary><ul>${common.map(li).join("")}</ul></details>`;
  return h;
}

function drill(id, catKey) {
  const p = MODEL[id].at(-1);
  const cat = CATEGORIES.find((c) => c.key === catKey);
  const fts = Object.entries(FT2CAT).filter(([, v]) => v === catKey).map(([k]) => k);
  const items = findingItems(p.row, fts);
  document.getElementById("drill-title").textContent = `${id} · ${cat.label} · ${p.states[catKey]}`;
  const body = catKey === "host_mounts"
    ? renderMountDrill(items, p.baselineRow, fts)
    : (items.length ? "<ul>" + items.map((i) => `<li>${typeof i === "object" ? JSON.stringify(i) : i}</li>`).join("") + "</ul>"
        : `<p class="muted">No accessible items (${p.states[catKey]}).</p>`);
  document.getElementById("drill-body").innerHTML =
    `<div class="fp">fingerprint: ${p.harnessVersion || "—"} · probe ${p.probe} · ${p.kernel}</div>` +
    (catKey === "local_services" ? localServicesContext(p.row) : "") + body;
  document.getElementById("drill").classList.remove("hidden");
}

// An unmeasured Local svc cell used to be indistinguishable from a blocked one.
// The probe now says which it is, so show that rather than leaving a reader to
// guess why a cell is "?" — and show what the kernel says is bound, which is
// the other half of the question and is deliberately never scored.
function localServicesContext(row) {
  const st = find(row, "local_probe_status")?.value;
  const listeners = find(row, "local_listeners")?.value;
  if (!st && !listeners) return "";

  const bits = [];
  if (st) {
    if (st.table && st.table !== "read") {
      bits.push(`socket table <b>${st.table}</b>${st.error ? ` — ${st.error}` : ""}`);
    } else if (st.table === "read") {
      bits.push(`socket table read via ${st.source} (${st.listeners_found ?? 0} bound)`);
    }
    if (st.udp_feedback && st.udp_feedback !== "working") {
      // Without a live refusal channel a UDP silence proves nothing, so the
      // probe reports no UDP finding at all rather than an empty one.
      bits.push(`UDP feedback <b>${st.udp_feedback}</b>: silence carries no information here`);
    }
    if (st.netns) bits.push(`netns ${st.netns}`);
  }
  const head = bits.length ? `<p class="muted">${bits.join(" · ")}</p>` : "";

  let inv = "";
  if (Array.isArray(listeners)) {
    inv = listeners.length
      ? `<p class="muted">Bound in this namespace (visibility, not reachability — not scored):</p>` +
        "<ul>" + listeners.map((l) => `<li>${l}</li>`).join("") + "</ul>"
      : `<p class="muted">Nothing bound in this namespace.</p>`;
  }
  return head + inv;
}

function renderFlips() {
  const fl = flips(MODEL);
  document.getElementById("flips").innerHTML = fl.length
    ? "<ul class='flip-list'>" + fl.map((f) =>
        `<li class="${f.degraded ? "deg" : "imp"}"><span class="badge">${f.degraded ? "▲ regression" : "▼ improvement"}</span>
         <code>${f.id}</code> — <b>${f.cat}</b> ${f.from}→${f.to}
         <span class="muted">@ ${f.ts.slice(0, 10)} · ${f.cause}</span></li>`).join("") + "</ul>"
    : "<p class='muted'>No flips yet.</p>";
}

function renderCharts() {
  // Chart A — exposure over time, one line per non-baseline identity.
  const ex = echarts.init(document.getElementById("chart-exposure"));
  const series = [];
  const versionMarks = [];
  for (const [id, pts] of Object.entries(MODEL)) {
    if (id.endsWith("/direct")) continue;
    series.push({
      name: id, type: "line", step: "end", showSymbol: true, symbolSize: 6,
      data: pts.map((p) => [p.ts, p.exposure]),
    });
    for (let i = 1; i < pts.length; i++)
      if (pts[i].harnessVersion && pts[i].harnessVersion !== pts[i - 1].harnessVersion)
        versionMarks.push({ xAxis: pts[i].ts, label: { formatter: `${id.split("/")[1]} ${pts[i].harnessVersion}`, rotate: 90, fontSize: 9 } });
  }
  if (series.length) series[0].markLine = { symbol: "none", silent: true, lineStyle: { type: "dashed", color: CHART_BORDER() }, data: versionMarks };
  ex.setOption({
    backgroundColor: "transparent",
    textStyle: { color: CHART_TEXT() },
    tooltip: { trigger: "axis", backgroundColor: cssVar("--cp-card"), borderColor: CHART_BORDER(), textStyle: { color: cssVar("--cp-text-heading") } },
    legend: { type: "scroll", top: 0, textStyle: { color: CHART_TEXT() } },
    grid: { top: 40, left: 40, right: 20, bottom: 30 },
    xAxis: { type: "time", ...CHART_AXIS },
    yAxis: { type: "value", name: "leaked cats", min: 0, max: 8, minInterval: 1, ...CHART_AXIS },
    series,
  });

  renderHeatmap();
  window.addEventListener("resize", () => { ex.resize(); HM && HM.resize(); });
}

let HM;
function renderHeatmap() {
  const id = document.getElementById("hm-identity").value;
  const pts = MODEL[id] || [];
  HM = HM || echarts.init(document.getElementById("chart-heatmap"));
  const val = { leaked: 2, blocked: 1, na: 0, unprovable: 0 };
  const data = [];
  pts.forEach((p, x) => CATEGORIES.forEach((c, y) => data.push([x, y, val[p.states[c.key]] ?? 0])));
  HM.setOption({
    backgroundColor: "transparent",
    textStyle: { color: CHART_TEXT() },
    tooltip: {
      formatter: (o) => `${CATEGORIES[o.value[1]].label} @ ${pts[o.value[0]].ts.slice(0, 10)}: ${["n/a", "blocked", "leaked"][o.value[2]]}`,
      backgroundColor: cssVar("--cp-card"), borderColor: CHART_BORDER(), textStyle: { color: cssVar("--cp-text-heading") },
    },
    grid: { top: 10, left: 90, right: 20, bottom: 60 },
    xAxis: { type: "category", data: pts.map((p) => p.ts.slice(5, 10)), axisLabel: { rotate: 45, color: CHART_TEXT() }, axisLine: CHART_AXIS.axisLine },
    yAxis: { type: "category", data: CATEGORIES.map((c) => c.label), axisLabel: { color: CHART_TEXT() }, axisLine: CHART_AXIS.axisLine },
    visualMap: {
      type: "piecewise", show: true, orient: "horizontal", bottom: 0, left: "center",
      textStyle: { color: CHART_TEXT() },
      pieces: [
        { value: 0, label: "n/a", color: cssVar("--cp-pill-bg") },
        { value: 1, label: "blocked", color: cssVar("--status-blocked") },
        { value: 2, label: "leaked", color: cssVar("--status-leaked") },
      ],
    },
    series: [{ type: "heatmap", data, label: { show: false } }],
  }, true);
}

// ── boot ─────────────────────────────────────────────────────────────────────────
async function boot() {
  let rows;
  for (const src of ["all-reports.json", "sample-data.json"]) {
    try { const res = await fetch(src); if (res.ok) { rows = await res.json(); break; } } catch { /* next */ }
  }
  if (!rows) { document.getElementById("matrix").textContent = "No data."; return; }

  MODEL = build(rows);
  renderMeta(rows);

  // OS filter options
  const oses = [...new Set(rows.map((r) => r.os))].sort();
  const osSel = document.getElementById("os-filter");
  for (const o of oses) osSel.add(new Option(o, o));
  osSel.addEventListener("change", (e) => { OSFILTER = e.target.value; renderMatrix(); });

  // heatmap identity options (non-baseline)
  const hmSel = document.getElementById("hm-identity");
  const nonBaseline = Object.keys(MODEL).filter((id) => !id.endsWith("/direct")).sort();
  for (const id of nonBaseline) hmSel.add(new Option(id, id));
  hmSel.value = nonBaseline.find((id) => id.includes("claude")) || nonBaseline[0];
  hmSel.addEventListener("change", renderHeatmap);

  renderMatrix();
  renderFlips();
  renderCharts();

  document.getElementById("drill-close").addEventListener("click", () =>
    document.getElementById("drill").classList.add("hidden"));
}
boot();
