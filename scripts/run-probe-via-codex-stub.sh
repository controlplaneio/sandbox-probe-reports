#!/usr/bin/env bash
# Run sandbox-probe via the REAL codex CLI with the model stubbed out (no LLM, no key). The general
# mock (scripts/mock-agent-api.mjs) answers codex's /v1/responses with a canned shell tool call that
# runs the probe; codex runs it inside its own sandbox — Seatbelt on macOS, bubblewrap+seccomp on
# Linux. Codex sandboxes only the shell child, so the mock stays reachable on localhost.
#
# CODEX_SANDBOX=on (default) confines the run with `workspace-write` (writes limited to the work
# dir, no network — the probe can still emit its report). CODEX_SANDBOX=off runs it "as is"
# (approvals + sandbox bypassed), an unconfined baseline to diff against.
#
# CODEX_NONO_PROFILE=<namespace>/<name> is the third variant — the `codex-nono` row. Codex runs
# under a *declared, vendor-published* nono registry profile instead of its own native sandbox,
# so a developer can read what each sandboxing choice costs on the same methodology. Codex's own
# sandbox is bypassed there so there is exactly ONE sandbox layer and a denial is unambiguously
# nono's, which is nono's own documented invocation for Codex. Nothing is passed to `nono run`
# but the profile: the confinement is entirely the vendor's, none of it ours.
#
# That row installs a registry pack, which mutates ~/.codex on the machine it runs on; removal is
# verified on exit whether the run succeeds or fails. See scripts/nono-pack.sh.
#
# Required env: PROBE (probe binary), OUT (report path).
# Optional env: CODEX_SANDBOX (on|off, default on), CODEX_NONO_PROFILE, RUNNER, PORT,
#               SCAN_ARGS (default "scan --tasksets baseline").
set -eo pipefail
source "$(dirname "$0")/stub-common.sh"
source "$(dirname "$0")/nono-pack.sh"

PORT="${PORT:-8789}"
CODEX_SANDBOX="${CODEX_SANDBOX:-on}"
stub_init

VERSION="$(stub_semver codex --version)"
# When confining on Linux, Codex wraps the probe in bubblewrap — record bwrap's version too (the
# sandbox engine the report reflects; kernel/OS is in the environment_detection finding). No-op on
# macOS (Seatbelt) / when unconfined.
SANDBOX_TOOL_TAG=""
if [ "$CODEX_SANDBOX" = "on" ] && command -v bwrap >/dev/null 2>&1; then
  BWRAP_VERSION="$(bwrap --version 2>/dev/null | awk 'NR==1{print $NF}')" || BWRAP_VERSION=""
  [ -n "$BWRAP_VERSION" ] && SANDBOX_TOOL_TAG=",bwrap=${BWRAP_VERSION}"
fi
HARNESS=codex
TAGS="runner=${RUNNER},harness=codex,sandbox=${CODEX_SANDBOX},codex=${VERSION}${SANDBOX_TOOL_TAG},mode=via-codex-stub"

export BASH_TIMEOUT_MS=600000   # carried by the mock into the tool input

if [ -n "$CODEX_NONO_PROFILE" ]; then
  # Say what this does to the machine BEFORE anything is installed, then snapshot and
  # arm removal, then install. The trap is live across the whole window in which the
  # pack exists — stub_start_mock replaces it below with _stub_cleanup, which calls
  # stub_extra_cleanup, so the verified removal survives the swap.
  nono_pack_warn "$CODEX_NONO_PROFILE"
  nono_pack_arm "$CODEX_NONO_PROFILE"
  stub_extra_cleanup() { nono_pack_restore; }
  trap nono_pack_restore EXIT
  nono_pack_install "$CODEX_NONO_PROFILE"

  # Its own harness identity, tagging the version actually resolved — so the row forms
  # its own time series and a flip is attributable to a specific published claim.
  NONO_VERSION="$(stub_semver nono --version)"
  PROFILE_VERSION="$(nono_pack_version "$CODEX_NONO_PROFILE")"

  # Read-only introspection, printed so the granted set is in the log rather than inferred.
  # `nono run` only summarises it as "+ N system/group paths (-v to show)", and that summary is
  # exactly what is needed to tell a CI-layout problem from a policy one — the distinction that
  # decides whether a red row is the vendor's gap or ours. Never fatal: this is diagnostics.
  echo "::group::resolved manifest for ${CODEX_NONO_PROFILE}"
  nono profile show "$CODEX_NONO_PROFILE" --format manifest 2>&1 | head -100 || true
  echo "::endgroup::"
  HARNESS=codex-nono
  TAGS="runner=${RUNNER},harness=codex-nono,sandbox=on,codex=${VERSION},nono=${NONO_VERSION}"
  TAGS="${TAGS},nono_profile=${CODEX_NONO_PROFILE}@${PROFILE_VERSION},mode=via-codex-stub"

  # Everything this run needs to read or write lives somewhere the profile ALREADY
  # grants, because granting a path ourselves would make the row measure our
  # configuration rather than the vendor's. nolabs-ai/codex grants r+w on $HOME/.codex,
  # so the probe binary, Codex's own state and the report all go in one directory under
  # it — which the verified cleanup removes before comparing snapshots.
  CODEX_HOME="$HOME/.codex/nono-row-$$"; export CODEX_HOME
  NONO_PACK_SCRATCH+=("$CODEX_HOME")
  mkdir -p "$CODEX_HOME"
  cp "$PROBE" "$CODEX_HOME/sandbox-probe"
  IN_GRANT="$CODEX_HOME/report.json"
  PROBE_CMD="$CODEX_HOME/sandbox-probe ${SCAN_ARGS} --tags ${TAGS} --output_path ${IN_GRANT}"
  stub_start_mock
else
  stub_start_mock
  # Scratch config so we never touch the runner's real ~/.codex; dummy key for the mock provider.
  CODEX_SCRATCH="$(mktemp -d)"; STUB_SCRATCH+=("$CODEX_SCRATCH")

  # Two spellings of one directory, because bash and codex.exe do not agree on it.
  #
  # Under `shell: bash` on windows-latest this is Git Bash: mktemp yields a POSIX path
  # ("/tmp/tmp.XXXX"), and MSYS rewrites path-shaped *arguments* handed to a native binary but
  # not *environment variables*. codex.exe would read CODEX_HOME verbatim, resolve it
  # drive-relative to C:\tmp\tmp.XXXX, never see the config written below, and leave that
  # directory behind — STUB_SCRATCH removes the POSIX one. cygpath exists only under MSYS, so
  # its absence is the no-op on Linux and macOS, where there is nothing to convert.
  CODEX_HOME="$(cygpath -w "$CODEX_SCRATCH" 2>/dev/null || printf %s "$CODEX_SCRATCH")"
  export CODEX_HOME

  # Codex's Windows sandbox is a restricted token, and it is OFF unless config.toml asks for it.
  # Measured 2026-08-24 against Codex 0.149.1, on a Windows 11 host and on windows-latest alike:
  # `--sandbox workspace-write` ALONE reports `read-only` and rejects every command, including a
  # bare `echo`, so the row would claim to be sandboxed and produce no report at all. This key is
  # minimum-to-run in the sense the README's flag table means — without it the sandbox does not
  # engage — and it is written as a file rather than passed as `-c windows.sandbox=...` because a
  # file is what was measured. Harmless on the sandbox=off row: with
  # --dangerously-bypass-approvals-and-sandbox the mode is danger-full-access either way, which
  # was control case B of that same measurement.
  if command -v cygpath >/dev/null 2>&1; then
    printf '[windows]\nsandbox = "unelevated"\n' >"$CODEX_SCRATCH/config.toml"
    echo "CODEX_HOME=$CODEX_HOME"
    cat "$CODEX_SCRATCH/config.toml"
  fi
fi
export MOCK_KEY=dummy OPENAI_API_KEY=dummy

# Confined = workspace-write (fs write limited to cwd, no network; the probe can still write its
# report). As-is = bypass approvals + sandbox entirely.
#
# Under a nono profile, Codex's own sandbox is bypassed on purpose: one boundary, not two, so a
# denial is unambiguously the declared profile's and the row measures that profile. This is nono's
# own documented invocation for Codex (nono.sh/docs/cli/clients/codex.md).
if [ -n "$CODEX_NONO_PROFILE" ] || [ "$CODEX_SANDBOX" = "off" ]; then
  SBX=(--dangerously-bypass-approvals-and-sandbox)
else
  SBX=(--sandbox workspace-write)
fi
# `nono run --profile <id> --` and nothing else: every restriction on this row is the vendor's.
#
# The `--read <dir>` nono suggests when codex cannot start is still NOT taken here, and the
# invocation is still the profile and nothing else. What was a CI-only failure is fixed by moving
# the binary rather than by widening the policy: a plain `npm install -g` on a GitHub runner
# lands codex in /opt/hostedtoolcache/..., a path no profile grants because no user has it, so
# the row died at exit 127 before measuring anything. The workflow now installs codex under
# $HOME/.codex, which this profile grants r+w itself — the same rule the block above already
# applies to the probe binary, Codex's state and the report.
NONO=()
[ -n "$CODEX_NONO_PROFILE" ] && NONO=(nono run --profile "$CODEX_NONO_PROFILE" --)
PROVIDER="model_providers.mock={ name = \"mock\", base_url = \"http://127.0.0.1:${PORT}/v1\", wire_api = \"responses\", env_key = \"MOCK_KEY\", request_max_retries = 0, stream_max_retries = 0 }"

echo "::group::${HARNESS} (stubbed model, sandbox=${CODEX_NONO_PROFILE:-$CODEX_SANDBOX})"
"${NONO[@]}" codex exec --skip-git-repo-check "${SBX[@]}" \
  -c approval_policy="never" \
  -c model_provider="mock" \
  -c "$PROVIDER" \
  -c model="mock-model" \
  "Run the sandbox probe and then stop." </dev/null || true
echo "::endgroup::"

# The report was written inside a path the profile grants; lift it out to OUT before the
# verified cleanup deletes that directory.
[ -n "$CODEX_NONO_PROFILE" ] && [ -f "$IN_GRANT" ] && cp "$IN_GRANT" "$OUT"

stub_finish "${HARNESS}(stub)"
