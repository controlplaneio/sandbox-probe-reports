# Reporting site — implementation checklist

Sequenced so the data track lands before the page needs anything to render.
Language and rationale: see [CONTEXT.md](../CONTEXT.md) and
[ADR 0001](adr/0001-client-side-site-over-data-branch.md).

**All four tracks have shipped.** This file is kept as the record of what was
built and where it landed, not as outstanding work. The one thing that never
worked is called out at the bottom.

## Track 1 — probe: expose the target registry

- [x] `sandbox-probe list-targets` — emits the probe's own checked targets as
      JSON. The probe is the single source of truth; `scripts/seed-decoys.sh`
      reads it, so seeding cannot drift from what is probed.
- [x] Parity guard — `TestEverySeedableTargetIsScanned` in the probe repo
      asserts that every seedable target is one the probe actually scans. A
      decoy planted where nothing looks is inert.

## Track 2 — seeder (prerequisite: site is hollow without it)

- [x] A seed step that reads `list-targets` and **soft-plants** a decoy at each
      path — writes only where nothing exists, so it never clobbers a real
      secret. Content-predicate targets are excluded: a generic decoy could
      never satisfy the predicate, and seeding `~/.gitconfig` corrupted git.
- [x] Runs **identically before the baseline and every sandbox run**. Parity is
      load-bearing: seeding one side only produces false 🟩 wins. It landed as a
      single invocation point in `scan-matrix.yaml` rather than in
      `scripts/stub-common.sh` as first sketched, because the runtime rows do
      not go through the stub plumbing and would have been seeded inconsistently.
- [x] IPC socket / named-pipe / process decoys — design closed, see the
      probe's [ADR 0002](https://github.com/controlplaneio/sandbox-probe/blob/main/docs/adr/0002-seed-ipc-and-process-targets.md)
      (it decides the probe's own registry shape, so it stays with the
      probe). Built on both sides: the `kind` field, the per-kind seeding
      core and the Windows named-pipe detection task are the probe's
      `seed`/`cleanup`; `seed-decoys.sh` dispatches to them and keeps the
      `file` kind, which is the only one bash can plant.
- [x] A cleanup pass after every scan in the matrix, including a failed one,
      so a reused runner accumulates none of the live artifacts (a process
      decoy, a Windows pipe server).

## Track 3 — publish pipeline (in scan-matrix.yaml)

- [x] `aggregate` job, `needs: [build, scan, attest]`, `if: always()`:
  - [x] download all report artifacts
  - [x] one commit → `gh-pages-data` branch at `data/<run-timestamp>/<os>-<harness>.json`
  - [x] rebuild `all-reports.json` by concatenating every report on the branch
  - [x] `actions/upload-pages-artifact` (site/ + all-reports.json) →
        `actions/deploy-pages`
- [x] No new triggers — rides the existing weekly cron + dispatch + `matrix/**`.
- [x] One-time: the orphan `gh-pages-data` branch exists; Pages is enabled with
      the GitHub Actions source. See "One-time setup" in the README.

## Track 4 — the page (site/, vanilla JS, no build)

All derivation client-side from `all-reports.json`:

- [x] Parse reports → group by identity `(os, harness)` → collapse to fingerprint
      points (latest wins).
- [x] Baseline-normalize each cell against the `direct` report of the same
      `(run-timestamp, os)`; flag unprovable when no baseline.
- [x] Categorize findings into the 8 capability categories (+ Other for unmapped);
      Privileged uses absolute euid-0 rule.
- [x] **Matrix view** — identities × categories, 3-state cells, enforcement +
      root badges, ▲/▼ change markers. The rows are the `direct` baseline and
      the agent-driven harnesses. The five generic runtimes were later retired
      rather than carried: see
      [ADR 0003](adr/0003-canary-nesting-and-the-comparability-criterion.md).
- [x] **Drill-down** — cell → actual values (paths/hosts/ports).
- [x] **Flip-log** — chronological flips, each attributed to the moved fingerprint
      component.
- [x] **Charts (ECharts via CDN + SRI, progressive enhancement)** — exposure
      step-line (0–8, calendar x, version-release markLines, multi-identity
      overlay) + per-capability status heatmap.
- [x] **Attestation view** — added after this plan was written. Diffs a declared
      nono profile against what the probe can actually reach.
- [x] Developed against the `reports/` fixtures until the first real aggregate
      run existed.

## What did not work

Three weeks of scheduled runs wrote 99 reports to `gh-pages-data` and published
none of them. Every `aggregate` job died at `actions/configure-pages` with
*"Get Pages site failed"*, because Pages had never been enabled on the
repository. The data half succeeded every time, so nothing in the Actions
summary said the site was dark. Enabling Pages is one API call; see the README.

The lesson worth keeping: this checklist's Track 3 said "enable Pages" and it
was ticked as part of a batch. A one-time setup step outside the source tree
cannot be verified by anything in the source tree, and needs its own check.

## Extendability check (must stay true)

- New harness → new row/line, automatic (identity from data).
- Harness that stops receiving runs → row/line leaves the same way, automatic.
- New finding type → mapped category, or **Other** (never dropped).
- New target → add to probe registry; seeder picks it up via `list-targets`.
