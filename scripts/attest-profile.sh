#!/usr/bin/env bash
# Run sandbox-probe under a *declared* nono registry profile and attest the result:
# the profile's resolved capability set diffed against what the probe could actually
# reach, with a same-host seeded unconfined baseline as the third input. This is the
# declared-versus-actual comparison (CONTEXT.md, "Attestation"); it is NOT a matrix
# row and produces no exposure score.
#
# Only the OS-level policy half of the pack is attested. The pack's other half is
# Codex plugin wiring — a marketplace entry, a config.toml fence block, hooks, a
# skill file — which is inert when the sandboxed command is not the real Codex
# binary. See docs/attestation-mapping.md.
#
# The profile is a parameter, not a constant: pointing this at any other registry
# profile produces that profile's attestation with no code change.
#
#   PROFILE=nolabs-ai/codex ./scripts/attest-profile.sh
#
# Required env: PROBE (probe binary path).
# Optional:     PROFILE (default nolabs-ai/codex), OUT (default site/attestation.json),
#               WORK (scratch dir), NONO_PACK_ACK=1 (required off CI — see below).
#
# THIS INSTALLS A NONO PACK, WHICH MUTATES ~/.codex ON THIS MACHINE. Removal is
# verified on exit whether this succeeds or fails; off CI it will not start until
# NONO_PACK_ACK=1 says you accept that. See scripts/nono-pack.sh.
set -eo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/nono-pack.sh"

: "${PROBE:?PROBE (probe binary path) is required}"
PROFILE="${PROFILE:-nolabs-ai/codex}"
OUT="${OUT:-$ROOT/site/attestation.json}"
WORK="${WORK:-$(mktemp -d)}"
PROBE_ABS="$(cd "$(dirname "$PROBE")" && pwd)/$(basename "$PROBE")"
mkdir -p "$WORK" "$(dirname "$OUT")"

# The probe binary and its report have to live somewhere the profile ALREADY grants.
# Adding a grant of our own would put a path in the observed set that the profile
# never declared — a gap this run invented — and would make the attestation a
# verdict on our configuration rather than the vendor's. nolabs-ai/codex grants r+w
# on $HOME/.codex, so both go in one directory under it, which the verified cleanup
# removes. Nothing is passed to `nono run` but the profile itself.
IN_GRANT_DIR="$HOME/.codex/sandbox-probe-attest-$$"
IN_GRANT="$IN_GRANT_DIR/report.json"

# ── 1. say what this does to the machine, before anything is installed ─────────
nono_pack_warn "$PROFILE"

# ── 2. the seeded unconfined baseline, same host, before the pack exists ───────
# Without it every declared grant pointing at a path that merely does not exist
# reads as a false overclaim rather than unprovable.
"$ROOT/scripts/seed-decoys.sh" "$PROBE_ABS"
"$PROBE_ABS" scan --tasksets baseline \
  --tags "harness=attest-baseline,profile=${PROFILE}" \
  --output_path "$WORK/baseline.json"

# ── 3. install the pack, cleanup armed first ──────────────────────────────────
nono_pack_arm "$PROFILE"
NONO_PACK_SCRATCH+=("$IN_GRANT_DIR")
trap nono_pack_restore EXIT
nono_pack_install "$PROFILE"

VERSION="$(nono_pack_version "$PROFILE")"
echo "attest: ${PROFILE} resolved to version ${VERSION}"

# The resolved capability set — never the authored profile. See nono_pack_manifest
# in scripts/nono-pack.sh for what that distinction costs if it is got wrong.
PACK_DIR="${NONO_CONFIG:-$HOME/.config/nono}/packages/${PROFILE%%@*}"
PROFILE_ID="${PROFILE%%@*}"
if ! MANIFEST_NAME="$(nono_pack_manifest "$PROFILE" "$WORK/capability-set.json")"; then
  echo "::error::no resolved capability manifest for ${PROFILE_ID} — nono's profile naming or manifest format has moved."
  echo "::error::Tried 'nono profile show ${PROFILE_ID}' and 'nono profile show ${PROFILE_ID##*/}', both --format manifest."
  echo "::error::What nono says, then the installed pack, follow."
  nono profile show "${PROFILE_ID##*/}" --format manifest || true
  nono profile list || true
  ls -R "$PACK_DIR" || true
  exit 1
fi
echo "attest: resolved capability manifest via 'nono profile show ${MANIFEST_NAME} --format manifest'"

# ── 4. the probe under the profile, no flag of ours ───────────────────────────
mkdir -p "$IN_GRANT_DIR"
cp "$PROBE_ABS" "$IN_GRANT_DIR/sandbox-probe"
echo "::group::probe under ${PROFILE}"
nono run --profile "$PROFILE" -- \
  "$IN_GRANT_DIR/sandbox-probe" scan --tasksets baseline \
  --tags "harness=attest,profile=${PROFILE},nono_profile_version=${VERSION}" \
  --output_path "$IN_GRANT" </dev/null || true
echo "::endgroup::"

if [ ! -f "$IN_GRANT" ]; then
  echo "::error::the probe produced no report under ${PROFILE} — nothing to attest"
  exit 1
fi
cp "$IN_GRANT" "$WORK/under-profile.json"

# ── 5. the diff — a pure function over the three documents ────────────────────
node "$ROOT/scripts/build-attestation.mjs" \
  --profile "$PROFILE" --version "$VERSION" \
  --capability-set "$WORK/capability-set.json" \
  --sandbox "$WORK/under-profile.json" \
  --baseline "$WORK/baseline.json" \
  --home "$HOME" \
  --out "$OUT"

echo "attest: wrote ${OUT} for ${PROFILE}@${VERSION}"
# The EXIT trap removes the pack and verifies the machine is as it was.
