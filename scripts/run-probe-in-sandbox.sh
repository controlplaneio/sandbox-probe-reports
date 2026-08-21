#!/usr/bin/env bash
# Run sandbox-probe DIRECTLY inside a sandbox runtime (no agent, no model). Distinct keyless OS
# sandbox mechanisms; the probe fingerprints each. RUNTIME selects the wrapper:
#   srt      — @anthropic-ai/sandbox-runtime: bubblewrap (Linux) / Seatbelt (macOS) + network proxy
#   firejail — SUID namespaces + whatever its own default profile applies (Linux)
#   nono     — capability sandbox: Landlock + seccomp-notify (Linux) / Seatbelt (macOS)
#
# Each is launched with no restriction this repository invented — only what the tool needs to start
# and to emit its report — so a blocked capability is the vendor's posture, not ours. None of the
# three blocks network egress: none of them does out of the box.
#
# These three restrict the *same* filesystem by policy, so they nest genuinely in the seeded parent.
# The rootfs-swapping runtimes (docker, podman, bwrap, nspawn, gvisor) were retired from the
# comparison — see the retirement note in README.md; they are not launchable here by design.
#
# Required env: PROBE, OUT, RUNTIME. Optional: RUNNER, PORT (unused), SCAN_ARGS.
set -eo pipefail

: "${PROBE:?PROBE (probe binary path) is required}"
: "${OUT:?OUT (report output path) is required}"
: "${RUNTIME:?RUNTIME (srt|firejail|nono) is required}"
RUNNER="${RUNNER:-$(uname -s)}"
SCAN_ARGS="${SCAN_ARGS:-scan --tasksets baseline}"

mkdir -p "$(dirname "$OUT")"
PROBE_ABS="$(cd "$(dirname "$PROBE")" && pwd)/$(basename "$PROBE")"
OUT_ABS="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"

# Capture the sandbox tool's own version into the report tags, so results are comparable across tool
# upgrades over time (the kernel/OS is recorded separately by the probe's environment_detection
# finding, on every run). awk consumes the whole stream (no `head` — that would SIGPIPE under
# pipefail); each extractor picks the version token from the tool's first --version line.
sandbox_version() {
  case "$1" in
    srt)      srt --version            2>/dev/null | awk 'NR==1{print $1}' ;;
    firejail) firejail --version       2>/dev/null | awk 'NR==1{print $NF}' ;;
    nono)     nono --version           2>/dev/null | awk 'NR==1{print $NF}' ;;
  esac
}
RUNTIME_VERSION="$(sandbox_version "$RUNTIME")" || RUNTIME_VERSION=""
TAGS="runner=${RUNNER},harness=${RUNTIME},${RUNTIME}=${RUNTIME_VERSION:-unknown},sandbox=on,mode=via-sandbox"
CMD=("$PROBE_ABS" $SCAN_ARGS --tags "$TAGS" --output_path "$OUT_ABS")

echo "::group::sandbox ${RUNTIME}"
case "$RUNTIME" in
  srt)
    # Deny-by-default; allow writes only to the workspace + tmp so the probe can emit its report.
    SETTINGS="$(mktemp)"
    cat > "$SETTINGS" <<JSON
{ "filesystem": { "denyRead": [], "allowRead": [], "allowWrite": ["${PWD}", "/tmp", "/private/tmp"], "denyWrite": [] },
  "network": { "allowedDomains": [], "deniedDomains": [] } }
JSON
    srt --settings "$SETTINGS" "${CMD[@]}" || true
    rm -f "$SETTINGS"
    ;;
  firejail)
    # Its own default profile, nothing added: --quiet only quiets firejail's banner. Bare firejail
    # has open network and full filesystem read/write; the network and seccomp flags this repo used
    # to pass were narrowings firejail does not apply itself (ticket #32).
    firejail --quiet "${CMD[@]}" || true
    ;;
  nono)
    # Read-only cwd, write only to the report dir. nono denies everything with zero flags and will
    # not start non-interactively, so these grants are the minimum to run at all, not a narrowing.
    # Network is left as nono ships it — allowed. stdin from /dev/null so a denial never blocks on
    # an interactive prompt.
    nono run --silent --allow-cwd --allow "$(dirname "$OUT_ABS")" "${CMD[@]}" </dev/null || true
    ;;
  *)
    echo "::error::unknown RUNTIME '${RUNTIME}'"; exit 1 ;;
esac
echo "::endgroup::"

if [ ! -f "$OUT" ]; then
  echo "::error::sandbox ${RUNTIME} did not produce ${OUT}"
  exit 1
fi
echo "sandbox ${RUNTIME} wrote ${OUT}"
