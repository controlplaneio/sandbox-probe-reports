# shellcheck shell=bash
# Pack lifecycle for the two nono registry-profile rows: the loud warning, the
# install, and the *verified* removal. Sourced by scripts/attest-profile.sh (the
# attestation run) and scripts/run-probe-via-codex-stub.sh (the codex-nono matrix
# row) — both install the same pack and both owe the same cleanup.
#
# Why this exists at all. Installing a nono registry pack is NOT side-effect free.
# Confirmed empirically against nono 0.68.0: `nono run --profile nolabs-ai/codex
# --dry-run -- echo hi` fully installed the pack and spliced Codex plugin wiring
# into the machine's real ~/.codex/config.toml (a `nono:<ns>-<name>` fenced block)
# and ~/.codex/plugins/. `--dry-run` skips *sandbox verification and execution*,
# not pack installation. So on anyone's own machine this is a real, unrequested
# modification to their agent configuration, and removal has to be an explicit
# step that is verified and that runs even when the run fails — never an
# assumption, and never conditional on success.
#
# Contract (source it; it is not executable):
#   nono_pack_warn <profile>     loud banner naming every path that gets mutated,
#                                printed BEFORE anything is installed. On a
#                                developer machine it refuses to continue without
#                                NONO_PACK_ACK=1.
#   nono_pack_arm <profile>      snapshot the mutation targets. Call before the
#                                install; the caller wires nono_pack_restore onto
#                                an EXIT trap immediately after.
#   nono_pack_install <profile>  remove-then-pull. Never assumes the pack install
#                                is idempotent, nor that the last run left a clean
#                                state — a repeat run starts from removed.
#   nono_pack_version <profile>  the version actually resolved, for the record.
#   nono_pack_restore            remove the pack and verify the snapshot is back.
#                                Fails the run, naming what is left behind, if not.
#   NONO_PACK_SCRATCH+=(path)    files this run itself created inside a mutated
#                                tree (a report written into a granted path);
#                                removed before the snapshot is compared.
#
# NONO_PACK_FAIL_AFTER_INSTALL=1 aborts right after the install. That is how the
# gated job proves cleanup survives a mid-run failure — the failure mode here is
# silent mutation of a real machine, so it is exercised, not asserted.

NONO_PACK_SCRATCH=()
NONO_PACK_PROFILE=""
NONO_PACK_BEFORE=""

# ~/.codex and ~/.agents are the trees the Codex pack splices into; the packages
# dir is where the pack itself lands. NONO_CONFIG follows nono's own env var.
nono_pack_paths() {
  local pack="${1%%@*}"
  printf '%s\n' \
    "$HOME/.codex" \
    "$HOME/.agents" \
    "${NONO_CONFIG:-$HOME/.config/nono}/packages/${pack}"
}

if command -v sha256sum >/dev/null 2>&1; then NONO_PACK_SHA=(sha256sum); else NONO_PACK_SHA=(shasum -a 256); fi

# One line per file (hash + path) and per directory, sorted. Missing trees contribute
# nothing, which is itself the state to restore — a tree that did not exist before must
# not exist after, and the empty directory husks a removal leaves behind are exactly the
# residue this has to catch. `-exec … +` rather than xargs: it runs nothing at all when
# there is no match, instead of running the hasher with no arguments and reading stdin.
nono_pack_snapshot() {
  local root
  while IFS= read -r root; do
    [ -e "$root" ] || continue
    if [ -f "$root" ]; then "${NONO_PACK_SHA[@]}" "$root"; continue; fi
    find "$root" -type f -exec "${NONO_PACK_SHA[@]}" {} + 2>/dev/null
    find "$root" -type d -print 2>/dev/null | sed 's/^/dir  /'
  done < <(nono_pack_paths "$1") | LC_ALL=C sort
}

nono_pack_warn() {
  local profile="$1"
  {
    echo
    echo "############################################################"
    echo "#  INSTALLING A NONO PACK MUTATES THIS MACHINE'S AGENT CONFIG"
    echo "############################################################"
    echo "#  profile: ${profile}"
    echo "#"
    echo "#  Installing '${profile}' splices Codex plugin wiring into your local"
    echo "#  agent configuration. This happens on INSTALL — nono's --dry-run skips"
    echo "#  sandbox verification and execution, NOT pack installation. Verified"
    echo "#  against nono 0.68.0."
    echo "#"
    echo "#  These paths will be written to and then restored:"
    nono_pack_paths "$profile" | sed 's/^/#    /'
    echo "#    ${HOME}/.codex/config.toml  (a 'nono:' fenced block is spliced in)"
    echo "#"
    echo "#  Removal ('nono remove ${profile}') runs on exit whether this run"
    echo "#  succeeds or fails, and the paths above are compared against a snapshot"
    echo "#  taken now. If anything is left behind this run fails and names it."
    echo "############################################################"
    echo
  } >&2

  # A CI runner is disposable; a developer's machine is not, so it has to opt in.
  if [ "${CI:-}" != "true" ] && [ "${NONO_PACK_ACK:-}" != "1" ]; then
    echo "::error::refusing to install ${profile}: set NONO_PACK_ACK=1 to accept the change above" >&2
    exit 1
  fi
}

nono_pack_arm() {
  NONO_PACK_PROFILE="$1"
  NONO_PACK_BEFORE="$(mktemp)"
  nono_pack_snapshot "$1" > "$NONO_PACK_BEFORE"
  echo "nono-pack: snapshotted $(wc -l < "$NONO_PACK_BEFORE" | tr -d ' ') entries before installing $1" >&2
}

nono_pack_install() {
  local profile="$1"
  # Remove first, unconditionally. A previous run that was killed between install
  # and cleanup leaves a half-spliced state, and `pull` over it is not defined to
  # be idempotent. Starting from removed is what makes a repeat run mean anything.
  nono remove "$profile" >/dev/null 2>&1 || true
  nono pull "$profile"
  [ "${NONO_PACK_FAIL_AFTER_INSTALL:-}" = "1" ] && { echo "nono-pack: aborting after install (fault injection)" >&2; exit 9; }
  return 0
}

# The version actually resolved, not the one asked for: `nolabs-ai/codex` resolves
# to whatever the registry serves today, and a verdict that cannot be traced to an
# exact published claim is worthless.
nono_pack_version() {
  local dir manifest version
  dir="${NONO_CONFIG:-$HOME/.config/nono}/packages/${1%%@*}"
  for manifest in "$dir/package.json" "$dir/nono-pack.json"; do
    [ -f "$manifest" ] || continue
    version="$(jq -r '.version // empty' "$manifest" 2>/dev/null)" || version=""
    if [ -n "$version" ]; then printf '%s\n' "$version"; return 0; fi
  done
  printf 'unknown\n'
}

# nono_pack_manifest <profile> <outfile> — the profile's RESOLVED capability set,
# written to outfile. Groups, aliases, inheritance and bypasses are already
# expanded here, which is the whole point: diffing the authored profile instead
# would mean reimplementing nono's resolver.
#
# Ask nono for it rather than reading a file out of the pack. This used to copy
# `<pack>/policy.json`, and from nono 0.74.0 that file is gone: the pack's
# registry-side policy.json is installed as `profiles/<install-as>.json`, which is
# the AUTHORED profile — it still carries `extends`, aliases and group references.
# Pointing at it would have attested the wrong document while still reporting a
# verdict, which is worse than failing. `nono profile show --format manifest` is
# the same resolution `nono run` applies, and its `version` is the manifestVersion
# the attestation records.
#
# Two names are tried, and the winner is echoed. `nono run --profile` takes the
# full `<ns>/<name>`, while the pack store keys profiles on the bare install-as
# name. Returns non-zero, having written nothing usable, if neither resolves.
nono_pack_manifest() {
  local profile_id="${1%%@*}" out="$2" candidate
  for candidate in "$profile_id" "${profile_id##*/}"; do
    nono profile show "$candidate" --format manifest > "$out" 2>/dev/null || continue
    # A manifest, not merely valid JSON: the whole attestation rests on this being
    # the resolved capability set, so a changed shape must fail here rather than
    # produce a verdict over the wrong document.
    jq -e 'has("version") and has("filesystem")' "$out" >/dev/null 2>&1 || continue
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}

# was_there reports whether the snapshot taken before the install already held
# this exact path, whatever its contents were. A path that was there belongs to
# whoever put it there and is never touched, even when the name matches what the
# pack would have created. The snapshot lines are `<sha>  <path>` and
# `dir  <path>`, so stripping the first field and its two spaces leaves the path.
nono_pack_was_there() {
  sed 's/^[^ ]*  //' "$NONO_PACK_BEFORE" 2>/dev/null | grep -qxF -- "$1"
}

# nono_pack_sweep_residue removes what `nono remove` leaves behind, and says so,
# so the gap stays visible instead of becoming invisible.
#
# Two kinds of residue, two rules, both narrow.
#
# The pack's own plugin copy under the installing namespace holds real files, so
# only that one namespace is removed, and only where the snapshot shows the path
# was absent before.
#
# Everything else nono leaves is empty: directories it created and did not take
# away, and a zero-byte config.toml where there was no configuration file at all.
# Those go only when they hold nothing — an empty directory or a zero-byte file
# that was not there before. Anything carrying content stays exactly where it is,
# so a real unreverted mutation still fails the run and names itself.
nono_pack_sweep_residue() {
  local ns="${NONO_PACK_PROFILE%%/*}"
  [ -n "$ns" ] || return 0
  local swept=0 d root p

  for d in "$HOME/.codex/plugins/cache/$ns" "$HOME/.codex/plugins/marketplaces/$ns"; do
    [ -e "$d" ] || continue
    nono_pack_was_there "$d" && continue
    rm -rf "$d" 2>/dev/null && swept=$((swept + 1))
  done

  # -depth so a husk emptied by this same pass can go with it: children are
  # listed before their parent, and the parent is reached after they are gone.
  # rmdir rather than rm -rf is the guard on directories. It refuses on one that
  # still holds anything, so a parent shared with something real survives.
  while IFS= read -r root; do
    [ -d "$root" ] || continue
    while IFS= read -r p; do
      nono_pack_was_there "$p" && continue
      if [ -d "$p" ]; then
        rmdir "$p" 2>/dev/null && swept=$((swept + 1))
      elif [ -f "$p" ] && [ ! -s "$p" ]; then
        rm -f "$p" 2>/dev/null && swept=$((swept + 1))
      fi
    done < <(find "$root" -depth 2>/dev/null)
  done < <(nono_pack_paths "$NONO_PACK_PROFILE")

  [ "$swept" -gt 0 ] &&
    echo "::warning::nono remove ${NONO_PACK_PROFILE} left ${swept} path(s) behind; swept them so the machine is as it was found" >&2
  return 0
}

nono_pack_restore() {
  local status=$?
  [ -n "$NONO_PACK_PROFILE" ] || return "$status"

  nono remove "$NONO_PACK_PROFILE" || echo "::warning::nono remove ${NONO_PACK_PROFILE} exited non-zero" >&2
  # Files this run put inside a granted tree are ours, not the pack's; they would
  # otherwise read as residue the pack failed to remove.
  [ "${#NONO_PACK_SCRATCH[@]}" -gt 0 ] && rm -rf "${NONO_PACK_SCRATCH[@]}" 2>/dev/null
  # `nono remove` does not take everything it created with it. Verified against
  # nono 0.69.0 and 0.74.0: the pack's own files under ~/.config/nono/packages
  # go, and these are left behind —
  #   ~/.codex/plugins/{cache,marketplaces}/<namespace>   the pack's plugin copy
  #   ~/.codex, ~/.codex/bin                              empty directories
  #   ~/.codex/config.toml                                zero bytes, where there
  #                                                       was no file at all
  # so the snapshot never comes back clean and every run reports the machine as
  # mutated. Finish the job nono started, rather than widening the snapshot to
  # tolerate it: this whole file exists to guarantee the machine is left as it
  # was found, and a residue we merely stop LOOKING at is still residue on
  # somebody's laptop. Nothing that holds content is touched, and nothing the
  # snapshot shows was already there is touched.
  nono_pack_sweep_residue

  local after diff_out
  after="$(mktemp)"
  nono_pack_snapshot "$NONO_PACK_PROFILE" > "$after"
  diff_out="$(diff "$NONO_PACK_BEFORE" "$after" || true)"
  rm -f "$after"

  if [ -n "$diff_out" ]; then
    echo "::error::nono remove ${NONO_PACK_PROFILE} did not restore local agent configuration" >&2
    echo "$diff_out" >&2
    echo "::error::'<' was there before this run, '>' is what this run left behind" >&2
    exit 1
  fi
  echo "nono-pack: verified — ${NONO_PACK_PROFILE} removed, agent configuration back as it was" >&2
  return "$status"
}
