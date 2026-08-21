#!/usr/bin/env bash
# Soft-plant harmless decoys at the probe's own seedable targets, so a sandbox
# blocking access to a credential becomes a *provable* result rather than "n/a"
# (nothing was there to read). See docs/reporting-site-plan.md, ADR 0001, and
# the probe's ADR 0002 for the IPC kinds.
#
# Soft: writes only where nothing already exists — never clobbers a real secret,
# which makes it safe to run on a developer laptop as well as a bare CI runner.
#
# PARITY IS LOAD-BEARING: this must run identically before the baseline (direct)
# run AND before every sandboxed run. Seeding only one side turns every sandbox
# into a false "blocked" win because the file was simply absent on the other.
#
# ONE INVOCATION POINT, TWO MODES (ADR 0002): the matrix, the smoke job and
# attest-profile.sh all call this one script — plant with no flag, remove with
# --cleanup — rather than a sibling script that could drift out of step with it.
# Planting `file` decoys is the only part still done here; every other kind
# (socket, process, Windows named pipe) is the probe's own `seed`/`cleanup`,
# because bash cannot bind() a socket or serve a named pipe. A new kind added to
# the probe's registry therefore needs no change in this file.
#
# Usage: seed-decoys.sh [--cleanup] <path-to-probe-binary>
# Honours $HOME (the probe reads the same $HOME to decide where targets live).
set -euo pipefail

MODE=seed
if [ "${1:-}" = "--cleanup" ]; then
  MODE=cleanup
  shift
fi
PROBE="${1:?usage: seed-decoys.sh [--cleanup] <probe-binary>}"
DECOY_CONTENT='sandbox-probe decoy — not a real secret. Safe to delete.'

if ! command -v jq >/dev/null 2>&1; then
  echo "seed-decoys: jq is required" >&2
  exit 1
fi

# Read the registry into a variable, so a failure is fatal. Piping straight into
# the loop below via `< <(...)` hides it: process substitution exit status is
# invisible to set -e and pipefail, so an unreadable registry used to "succeed"
# with `planted 0` and every downstream comparison silently became "nothing was
# there to read". An empty seedable set is the same failure wearing a different
# hat. The `exit` below ends the script, not a subshell — this is called as a
# statement, never inside `$(...)`.
TARGETS=""
read_seedable_files() {
  # File targets only: a socket, pipe or process decoy is not something bash can
  # create, and a regular file written at one would shadow the target the
  # probe's own `seed` plants there.
  TARGETS=$("$PROBE" list-targets | jq -r '.[] | select(.seedable and .kind == "file") | .path')
  if [ -z "$TARGETS" ]; then
    echo "seed-decoys: $PROBE list-targets returned no seedable targets" >&2
    exit 1
  fi
  # Windows registry paths come back with backslashes; dirname and the MSYS path
  # layer under `shell: bash` only agree on "/". A POSIX registry path is $HOME
  # plus fixed segments and never contains a backslash, so this is a no-op there.
  TARGETS=${TARGETS//\\//}
}

# The probe's own summary line is a contract, not decoration: if it stops being
# readable the counts below would silently under-report, so an unparseable line
# is fatal for the same reason an unreadable registry is.
COUNTS=()
probe_count() { # <regex> <probe output> -> COUNTS
  local re=$1
  if [[ ! $2 =~ $re ]]; then
    echo "seed-decoys: unrecognised summary from '$PROBE': $2" >&2
    exit 1
  fi
  COUNTS=("${BASH_REMATCH[@]}")
}

if [ "$MODE" = cleanup ]; then
  # The probe first — it needs no registry read, so a registry that has become
  # unreadable cannot strand the live artifacts (a seeded process, a pipe server).
  probe_count 'removed ([0-9]+)' "$("$PROBE" cleanup)"
  removed=${COUNTS[1]}
  read_seedable_files
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    # Identity by content: only ever a regular file still holding exactly the
    # decoy line. A real secret that has since appeared at a registry path — or
    # a decoy someone has edited — is left alone.
    [ -f "$path" ] && [ "$(cat "$path")" = "$DECOY_CONTENT" ] || continue
    if rm -f "$path"; then removed=$((removed + 1)); fi
  done <<<"$TARGETS"
  echo "seed-decoys: removed ${removed} decoy artifact(s)"
  exit 0
fi

read_seedable_files
planted=0 skipped=0
while IFS= read -r path; do
  [ -n "$path" ] || continue
  if [ -e "$path" ]; then
    skipped=$((skipped + 1))          # soft: leave real files (and prior decoys) untouched
    continue
  fi
  mkdir -p "$(dirname "$path")" 2>/dev/null || { skipped=$((skipped + 1)); continue; }
  if printf '%s\n' "$DECOY_CONTENT" >"$path" 2>/dev/null; then
    planted=$((planted + 1))
  else
    skipped=$((skipped + 1))          # unwritable (e.g. permission) — not fatal
  fi
done <<<"$TARGETS"

# Every other kind, off the same registry: sockets, processes and Windows named
# pipes. Per-entry failures are the probe's to skip, not to abort on.
probe_count 'planted ([0-9]+), skipped ([0-9]+)' "$("$PROBE" seed)"
planted=$((planted + COUNTS[1]))
skipped=$((skipped + COUNTS[2]))

echo "seed-decoys: planted ${planted}, skipped ${skipped} (already present / unwritable)"
