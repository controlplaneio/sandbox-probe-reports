# Host mounts cell moves under the corrected mount enumerator

Record for [`sandbox-probe#43`](https://github.com/chrisns/sandbox-probe/issues/43)
(spec [#7](https://github.com/chrisns/sandbox-probe/issues/7) — the mount
enumerator missed real bind mounts and produced a false 🟩 blocked).

> Issue links in this file point at `chrisns/sandbox-probe`, the fork this work
> was tracked on before it moved to `controlplaneio`. That repository is
> archived, not deleted, so they still resolve.

The corrected enumerator reports mounts the old source-shape filter dropped, so
some harnesses' **Host mounts** cell moves 🟩 blocked → 🟥 leaked. **That is the
fix working, not a regression.** A cell that moves is new information about that
sandbox and is recorded here rather than re-baselined away.

Unchanged by this, and asserted so: the exposure scale (0–8), the cell-state
rules and the set of capability categories. Only one category's *inputs* change.

## How the record is produced

```sh
node scripts/mount-cell-moves.mjs <before.json> <after.json>
```

Both arguments are `all-reports.json` manifests as built by
`scripts/build-site-data.mjs` — one matrix run on the probe as pinned before the
fix, one on the bumped pin. The comparison loads `site/app.js` and uses the
site's own `build()`/`cellStates()`, so the record cannot drift from what the
matrix page shows. It exits non-zero if any category other than Host mounts
changes state for any harness.

Paste its output under [Result](#result).

## Result

**Not yet run.** The comparison needs a probe release carrying the corrected
enumerator, and this repository's pin bumped to it — the fifth acceptance
criterion of #43, and neither exists yet:

- The pin is still the placeholder `v1.1.0` (see the README), which predates
  both the fix and `list-targets`. Tracked as
  [sandbox-probe#14](https://github.com/chrisns/sandbox-probe/issues/14).
- Nothing can be derived from the stored fixtures in the interim: every report
  under `reports/` carries only `sandbox_detection` findings — they are
  fingerprint fixtures, not full scans — and no real report in this repository
  contains a `mounted_volumes_detections` finding at all. The only mount data
  present is in `site/sample-data.json`, which is synthetic
  (`scripts/gen-sample-data.mjs`) and therefore evidence of nothing.

So the set of harnesses whose cell moves is **unknown until a real matrix run on
the bumped pin**. Two things are already known about its shape:

- The runtime that surfaced the bug (gVisor) is retired from the comparison for
  methodology reasons, so it will not appear here.
- The macOS and Windows rows cannot move: the affected enumerator is
  Linux-specific.

Fill this section with the tool's output on the first matrix run after the pin
bump, and record the moves as corrected readings.
