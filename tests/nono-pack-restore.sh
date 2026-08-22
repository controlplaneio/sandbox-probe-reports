#!/usr/bin/env bash
# The half of the pack lifecycle that can be proven without a registry: does the verified removal
# actually notice when a machine is NOT put back? Run against a throwaway $HOME and a stub `nono`,
# so it needs no network, no real nono and no real agent configuration — and it is what fails if
# scripts/nono-pack.sh's snapshot/compare ever stops catching residue.
#
# The real-registry half (does `nono remove` reverse a real pack) is exercised in the gated
# `attest` job in .github/workflows/scan-matrix.yaml, where a mutation of a real home directory
# is acceptable. Here nothing outside $WORK is touched.
#
# Run: tests/nono-pack-restore.sh
set -eo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A stub `nono` that splices on pull and, depending on NONO_STUB_LEAK, does or does not reverse it.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/nono" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  pull)
    mkdir -p "$HOME/.codex/plugins/nono" "$NONO_CONFIG/packages/nolabs-ai/codex"
    mkdir -p "$HOME/.codex/plugins/cache/nolabs-ai/nono" "$HOME/.codex/plugins/marketplaces/nolabs-ai"
    mkdir -p "$HOME/.codex/bin"
    echo 'plugin' > "$HOME/.codex/plugins/nono/plugin.json"
    echo '{"version":"9.9.9"}' > "$NONO_CONFIG/packages/nolabs-ai/codex/package.json"
    printf '# nono:nolabs-ai-codex\ninstructions = "..."\n' >> "$HOME/.codex/config.toml"
    ;;
  remove)
    rm -rf "$NONO_CONFIG/packages/nolabs-ai/codex"
    [ "${NONO_STUB_LEAK:-}" = "1" ] && exit 0   # the bug: wiring left spliced in
    rm -rf "$HOME/.codex/plugins/nono"
    sed -i.bak '/# nono:nolabs-ai-codex/,+1d' "$HOME/.codex/config.toml"; rm -f "$HOME/.codex/config.toml.bak"
    # NONO_STUB_CACHE reproduces what real nono does, seen in the gated attest
    # job against 0.69.0 and 0.74.0: the pack's own files go, and what stays is
    # the plugin cache under the installing namespace, the empty parent husks,
    # the `bin` directory, and a config.toml emptied of everything but never
    # deleted. The unflagged path is the hypothetical where nono cleans up
    # after itself.
    [ "${NONO_STUB_CACHE:-}" = "1" ] && exit 0
    rm -rf "$HOME/.codex/plugins" "$HOME/.codex/bin"
    [ -s "$HOME/.codex/config.toml" ] || rm -f "$HOME/.codex/config.toml"
    ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/nono"
export PATH="$WORK/bin:$PATH"

# One case: a throwaway HOME carrying agent config that already existed.
new_home() {
  local h="$WORK/home-$1"
  rm -rf "$h"; mkdir -p "$h/.codex"
  printf 'model = "gpt-5"\n' > "$h/.codex/config.toml"
  printf '%s' "$h"
}

run_case() {              # run_case <name> <leak?> -> prints "status=N" and the output
  local home; home="$(new_home "$1")"
  HOME="$home" NONO_CONFIG="$home/.config/nono" NONO_STUB_LEAK="$2" CI=true \
    bash -c '
      set -eo pipefail
      source "'"$ROOT"'/scripts/nono-pack.sh"
      nono_pack_warn nolabs-ai/codex
      nono_pack_arm nolabs-ai/codex
      trap nono_pack_restore EXIT
      nono_pack_install nolabs-ai/codex
      echo "resolved version: $(nono_pack_version nolabs-ai/codex)"
    ' 2>&1
  echo "status=$?"
  printf '%s\n' "--- config.toml after ---"
  cat "$home/.codex/config.toml"
}

fail() { echo "FAIL: $1" >&2; exit 1; }

# 1. removal really removes -> the run passes and the machine is byte-identical to before.
clean="$(run_case clean "" || true)"
grep -q 'nono-pack: verified' <<<"$clean" || fail "a clean removal should verify: $clean"
grep -q 'status=0' <<<"$clean" || fail "a clean removal should not fail the run: $clean"
grep -q 'resolved version: 9.9.9' <<<"$clean" || fail "the resolved version should be read from the pack: $clean"
grep -q 'nono:nolabs-ai-codex' <<<"$clean" && fail "the fence block should be gone: $clean"

# 2. removal that leaves wiring spliced in -> the run FAILS and names what is left behind.
leaked="$(run_case leaked 1 || true)"
grep -q 'did not restore local agent configuration' <<<"$leaked" || fail "residue must fail the run: $leaked"
grep -q 'status=1' <<<"$leaked" || fail "residue must exit non-zero: $leaked"
grep -q 'plugin.json' <<<"$leaked" || fail "the failure must name the file left behind: $leaked"

# 3. the fault injection the gated job relies on: abort after install, cleanup still verified.
faulted="$(NONO_PACK_FAIL_AFTER_INSTALL=1 run_case faulted "" || true)"
grep -q 'nono-pack: verified' <<<"$faulted" || fail "cleanup must run after a mid-run failure: $faulted"
grep -q 'status=9' <<<"$faulted" || fail "the injected failure must still fail the run: $faulted"

# 4. the real nono behaviour: `nono remove` leaves its plugin cache under the installing
#    namespace. The sweep in nono_pack_restore finishes the job, so the run still verifies
#    rather than reporting the machine as permanently mutated on every single run.
cached="$(NONO_STUB_CACHE=1 run_case cached "" || true)"
grep -q 'nono-pack: verified' <<<"$cached" || fail "the plugin-cache residue must be swept so restore verifies: $cached"
grep -q 'path(s) behind' <<<"$cached" || fail "the sweep must say nono left residue rather than hiding it: $cached"
grep -q 'status=0' <<<"$cached" || fail "a swept run should not fail: $cached"

# 5. the sweep must not touch anything the machine already had. Same residue shape as
#    case 4, but present BEFORE the install, so it belongs to whoever put it there —
#    including an empty file, which is otherwise exactly what the sweep removes.
home="$(new_home preexisting)"
mkdir -p "$home/.codex/plugins/cache/nolabs-ai/theirs" "$home/.codex/theirs"
printf 'theirs\n' > "$home/.codex/plugins/cache/nolabs-ai/theirs/keep.json"
: > "$home/.codex/keep-me-empty"
HOME="$home" NONO_CONFIG="$home/.config/nono" NONO_STUB_CACHE=1 CI=true \
  bash -c '
    set -eo pipefail
    source "'"$ROOT"'/scripts/nono-pack.sh"
    nono_pack_warn nolabs-ai/codex
    nono_pack_arm nolabs-ai/codex
    trap nono_pack_restore EXIT
    nono_pack_install nolabs-ai/codex
  ' >/dev/null 2>&1 || true
[ -f "$home/.codex/plugins/cache/nolabs-ai/theirs/keep.json" ] \
  || fail "the sweep removed a namespace that existed before the install"
[ -f "$home/.codex/keep-me-empty" ] \
  || fail "the sweep removed an empty file that existed before the install"
[ -d "$home/.codex/theirs" ] \
  || fail "the sweep removed an empty directory that existed before the install"

# 6. the shape the CI runner actually has: no agent configuration at all beforehand, so
#    every directory and file nono leaves is one it created. `nono remove` empties
#    config.toml rather than deleting it, and leaves ~/.codex and ~/.codex/bin standing.
#    All of it is empty, so all of it goes and the run verifies.
home="$WORK/home-bare"; rm -rf "$home"; mkdir -p "$home"
bare="$(HOME="$home" NONO_CONFIG="$home/.config/nono" NONO_STUB_CACHE=1 CI=true \
  bash -c '
    set -eo pipefail
    source "'"$ROOT"'/scripts/nono-pack.sh"
    nono_pack_warn nolabs-ai/codex
    nono_pack_arm nolabs-ai/codex
    trap nono_pack_restore EXIT
    nono_pack_install nolabs-ai/codex
  ' 2>&1; echo "status=$?")"
grep -q 'nono-pack: verified' <<<"$bare" || fail "an empty-husk residue must be swept so restore verifies: $bare"
grep -q 'status=0' <<<"$bare" || fail "a swept run should not fail: $bare"
[ -e "$home/.codex" ] && fail "the sweep left ~/.codex standing on a machine that had none"

# 7. content is never swept. A leftover file with something in it is a real unreverted
#    mutation, so it must still fail the run even though its parents are empty husks.
home="$WORK/home-content"; rm -rf "$home"; mkdir -p "$home"
kept="$(HOME="$home" NONO_CONFIG="$home/.config/nono" NONO_STUB_CACHE=1 CI=true \
  bash -c '
    set -eo pipefail
    source "'"$ROOT"'/scripts/nono-pack.sh"
    nono_pack_warn nolabs-ai/codex
    nono_pack_arm nolabs-ai/codex
    trap nono_pack_restore EXIT
    nono_pack_install nolabs-ai/codex
    printf "left behind\n" > "$HOME/.codex/bin/stray"
  ' 2>&1; echo "status=$?")"
grep -q 'did not restore local agent configuration' <<<"$kept" || fail "a file with content must fail the run: $kept"
grep -q 'stray' <<<"$kept" || fail "the failure must name the file left behind: $kept"
[ -f "$home/.codex/bin/stray" ] || fail "the sweep removed a file that had content in it"

# 8. off CI, an unacknowledged install refuses rather than mutating anything.
home="$(new_home refuse)"
if HOME="$home" NONO_CONFIG="$home/.config/nono" CI="" NONO_PACK_ACK="" \
   bash -c 'set -eo pipefail; source "'"$ROOT"'/scripts/nono-pack.sh"; nono_pack_warn nolabs-ai/codex' >/dev/null 2>&1
then fail "an unacknowledged run on a developer machine must refuse to install"; fi

echo "ok - verified removal restores the machine, and fails the run naming the residue when it cannot"
