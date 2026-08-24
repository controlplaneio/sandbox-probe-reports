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

**Not run yet. The blocker is gone, so it can be run now.**

The comparison needed a probe release carrying the corrected enumerator, and
this repository's pin bumped to it — the fifth acceptance criterion of #43.
Both conditions are met as of 22 August 2026, and this section is stale in the
other direction now: it said neither existed, and both do.

- The pin is `v6.7.3` (`go.mod`), which carries the corrected enumerator. It is
  no longer the `v1.1.0` placeholder this section described.
- Real reports now carry `mounted_volumes_detections`. Sampled from the
  published run of 24 August: `linux-direct` 14 entries,
  `linux-claude-sandbox` 59, `macos-codex-sandbox` 0. So the fixtures objection
  below no longer holds either — there is real mount data to compare.

That `linux-claude-sandbox` reports **more** mounts than the unconfined
`linux-direct` baseline is the shape this document predicted, and is exactly
what a 🟩 → 🟥 move looks like. It is not analysed here. Run the tool as
described above and record the moves properly, rather than reading two numbers
out of one sample.

Two things remain true about the shape of the answer:

- The runtime that surfaced the bug (gVisor) is retired from the comparison for
  methodology reasons, so it will not appear here.
- The macOS and Windows rows cannot move: the affected enumerator is
  Linux-specific.

Fill this section with the tool's output and record the moves as corrected
readings. Nothing blocks that now.
