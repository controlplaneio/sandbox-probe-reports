#!/usr/bin/env bash
# Run sandbox-probe via the REAL GitHub Copilot CLI with the model stubbed out (no LLM, no key, no
# GitHub account). The general mock (scripts/mock-agent-api.mjs) answers Copilot's
# /v1/chat/completions with a canned bash tool call that runs the probe. Copilot runs it inside its
# own sandbox, which is Microsoft Execution Containers (MXC): Seatbelt on macOS, bubblewrap on
# Linux, ProcessContainer on Windows. Copilot sandboxes only the shell child, so the mock stays
# reachable on localhost.
#
# COPILOT_PROVIDER_BASE_URL activates "BYOK" mode, and BYOK needs no GitHub authentication. That is
# what makes this row runnable in CI with no credential and no AI credits.
#
# COPILOT_SANDBOX=on (default) confines the run. Enabling it needs BOTH `sandbox.enabled` in
# settings.json AND experimental features, because `/sandbox` is only registered when experimental
# features are on. There is no --sandbox flag in Copilot CLI 1.0.80. Nothing else is set, so the
# report reflects the vendor's own default policy, not ours: read/write cwd, read PATH dirs, the
# temp dir and the user profile, outbound network allowed, per-command bypass available.
# COPILOT_SANDBOX=off runs it "as is", an unconfined baseline to diff against.
#
# The --allow-all-* flags are Copilot's PERMISSION layer, which decides what the model may ask for.
# They are independent of the OS sandbox, which decides what the shell child may reach. Both rows
# pass them, so the only difference between the two rows is the sandbox itself.
#
# Required env: PROBE (probe binary), OUT (report path).
# Optional env: COPILOT_SANDBOX (on|off, default on), RUNNER, PORT,
#               SCAN_ARGS (default "scan --tasksets baseline").
set -eo pipefail
source "$(dirname "$0")/stub-common.sh"

PORT="${PORT:-8796}"
COPILOT_SANDBOX="${COPILOT_SANDBOX:-on}"
stub_init

VERSION="$(stub_semver copilot --version)"
# When confining on Linux, MXC wraps the probe in bubblewrap — record bwrap's version too (the
# sandbox engine the report reflects). No-op on macOS (Seatbelt) and Windows (ProcessContainer).
SANDBOX_TOOL_TAG=""
if [ "$COPILOT_SANDBOX" = "on" ] && command -v bwrap >/dev/null 2>&1; then
  BWRAP_VERSION="$(bwrap --version 2>/dev/null | awk 'NR==1{print $NF}')" || BWRAP_VERSION=""
  [ -n "$BWRAP_VERSION" ] && SANDBOX_TOOL_TAG=",bwrap=${BWRAP_VERSION}"
fi
TAGS="runner=${RUNNER},harness=copilot,sandbox=${COPILOT_SANDBOX},copilot=${VERSION}${SANDBOX_TOOL_TAG},mode=via-copilot-stub"

export BASH_TIMEOUT_MS=600000   # carried by the mock into the tool input

# On Windows, Copilot's shell tool is `powershell`, and inside the sandbox that PowerShell starts
# WITHOUT its default drive provider initialised, so a relative path does not resolve:
#   The term './sandbox-probe.exe' is not recognized as a name of a cmdlet, function, script file…
# Measured on windows-latest, run 32854833208: the unconfined row ran the identical relative
# command and produced a report, and only the sandboxed one failed. So this is the sandbox
# breaking the cwd, not PowerShell or the launcher.
#
# Absolute native paths need no cwd at all. `cygpath -wa` is the honest Windows test here — it is
# present exactly where the translation problem is, and absent on Linux and macOS, which keep the
# relative form every other row uses.
if command -v cygpath >/dev/null 2>&1; then
  PROBE_CMD="$(cygpath -wa "$PROBE") ${SCAN_ARGS} --tags ${TAGS} --output_path $(cygpath -wa "$OUT")"
  echo "windows: absolutised PROBE_CMD -> ${PROBE_CMD}"
fi

stub_start_mock

# Scratch config so we never touch the runner's real ~/.copilot. COPILOT_HOME also redirects the
# session store and the log dir, so a run leaves nothing behind.
COPILOT_HOME="$(mktemp -d)"; export COPILOT_HOME; STUB_SCRATCH+=("$COPILOT_HOME")
if [ "$COPILOT_SANDBOX" = "on" ]; then SBX=true; else SBX=false; fi
printf '{"experimental":true,"sandbox":{"enabled":%s}}\n' "$SBX" >"$COPILOT_HOME/settings.json"

# BYOK: point Copilot at the mock. "completions" is the default wire API and is the one the mock
# answers on /v1/chat/completions. A model is mandatory in BYOK mode even though the mock ignores it.
export COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:${PORT}/v1"
export COPILOT_PROVIDER_TYPE=openai
export COPILOT_PROVIDER_WIRE_API=completions
export COPILOT_PROVIDER_API_KEY=dummy
export COPILOT_MODEL=mock-model

echo "::group::copilot (stubbed model, sandbox=${COPILOT_SANDBOX})"
echo "COPILOT_HOME=$COPILOT_HOME"; cat "$COPILOT_HOME/settings.json"
# --allow-all-tools is required for non-interactive mode. --no-remote-export keeps the session off
# GitHub, which BYOK has no token for anyway. Nonzero exit is tolerated; the report is the signal.
copilot --experimental \
  --allow-all-tools --allow-all-paths --allow-all-urls \
  --no-auto-update --no-remote --no-remote-export --no-color \
  -p "Run the sandbox probe and then stop." </dev/null || true
echo "::endgroup::"

stub_finish "copilot(stub)"
