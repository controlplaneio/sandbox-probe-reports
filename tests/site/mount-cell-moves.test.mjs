// Ticket #43: the before/after Host mounts comparison that produces the record.
// Fixtures stand in for two matrix runs — one with the probe as pinned before
// the mount-enumerator fix, one after. No probe, no network, no agent CLI.
// Run: node tests/site/mount-cell-moves.test.mjs
import assert from "node:assert/strict";
import { compare, renderMarkdown } from "../../scripts/mount-cell-moves.mjs";

const report = (commit, findings) => ({
  probeBinary: { commit },
  metadata: { tags: ["os=linux"] },
  findings,
});
const row = (harness, commit, findings, ts = "2026-07-30T08:00:00Z") => ({
  os: "linux",
  harness,
  runTimestamp: ts,
  report: report(commit, findings),
});
const mounts = (v) => ({ findingType: "mounted_volumes_detections", value: v });
const reads = (v) => ({ findingType: "sensitive_readable_paths", value: v });

// -- the move: a bind mount the old enumerator dropped --
{
  // before: the enumerator's source-shape filter drops the bind, so the
  // sandbox reports nothing and the cell reads blocked.
  const before = [
    row("direct", "old", [mounts(["/"]), reads(["/etc/hostname"])]),
    row("claude-sandbox", "old", [mounts([]), reads([])]),
    row("codex-sandbox", "old", [mounts([]), reads([])]),
  ];
  // after: the inverted filter reports it, carrying the mount root.
  const after = [
    row("direct", "new", [mounts([{ source: "/dev/sda1", target: "/", fsType: "ext4", mountRoot: "/" }]), reads(["/etc/hostname"])], "2026-07-31T08:00:00Z"),
    row("claude-sandbox", "new", [
      mounts([
        { source: "/dev/sda1", target: "/", fsType: "ext4", mountRoot: "/" },
        { source: "/dev/sda1", target: "/mnt/host-decoy", fsType: "ext4", mountRoot: "/home/runner/decoy" },
      ]),
      reads([]),
    ], "2026-07-31T08:00:00Z"),
    row("codex-sandbox", "new", [mounts([]), reads([])], "2026-07-31T08:00:00Z"),
  ];

  const { moved, unchanged, otherMoved } = compare(before, after);

  assert.deepEqual(
    moved.map((m) => [m.id, m.from, m.to]),
    [["linux/claude-sandbox", "blocked", "leaked"]],
    "only the harness whose cell actually moves is listed"
  );
  assert.deepEqual(moved[0].mounts, ["/mnt/host-decoy"], "the mount responsible is named, baseline-shared mounts excluded");
  assert.ok(
    unchanged.some((u) => u.id === "linux/codex-sandbox" && u.state === "blocked"),
    "a harness whose cell does not move is confirmed unchanged"
  );
  assert.deepEqual(otherMoved, [], "no capability category other than Host mounts changes state");

  const md = renderMarkdown({ moved, unchanged, otherMoved });
  assert.ok(md.includes("linux/claude-sandbox") && md.includes("/mnt/host-decoy"), "the record names the harness and the mount");
}

// -- a non-Host-mounts move is caught rather than absorbed into the record --
{
  const before = [
    row("direct", "old", [mounts(["/"]), reads(["/etc/hostname"])]),
    row("claude-sandbox", "old", [mounts([]), reads([])]),
  ];
  const after = [
    row("direct", "new", [mounts(["/"]), reads(["/etc/hostname"])], "2026-07-31T08:00:00Z"),
    row("claude-sandbox", "new", [mounts([]), reads(["/etc/hostname"])], "2026-07-31T08:00:00Z"),
  ];
  const { moved, otherMoved } = compare(before, after);
  assert.deepEqual(moved, [], "Host mounts did not move here");
  assert.deepEqual(
    otherMoved.map((o) => [o.id, o.category, o.from, o.to]),
    [["linux/claude-sandbox", "FS read", "blocked", "leaked"]],
    "a state change in another category is reported, not silently accepted"
  );
}

console.log("ok - Host mounts moves recorded with the mount responsible; other categories asserted unchanged");
