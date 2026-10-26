#!/usr/bin/env bash
# Make capability-bearing user namespaces available to the sandboxes that need them, and SAY what
# the host actually allows afterwards.
#
# srt's seccomp isolation layer runs `apply-seccomp`, which creates a user+PID+mount namespace
# INSIDE the one bubblewrap already made, and writes /proc/self/setgroups there. Ubuntu 24.04+
# enables kernel.apparmor_restrict_unprivileged_userns, which lets unshare(CLONE_NEWUSER) succeed
# while stripping capabilities from the namespace it returns, so that write fails with
# "nested userns is capability-restricted; caller must provide CAP_SYS_ADMIN" and the row produces
# no report. srt's README names the sysctl as the cure.
#
# ubuntu-latest moved to ubuntu-26.04 (image 20261012), where clearing that one knob was NOT
# enough: the srt and claude-sandbox rows still failed with the same message while the step's own
# output showed kernel.apparmor_restrict_unprivileged_userns = 0. So this clears every related
# knob the host has and then PROVES the result with a nested unshare rather than assuming it,
# because the failure mode this replaces was a setting that looked applied and was not.
#
# Non-fatal by design: it prints what it found and exits 0. A host that still refuses should fail
# in the row that needs it, with that row's own evidence, not here.
set -o pipefail

say() { printf '%s\n' "$*"; }

if [ "$(uname -s)" != "Linux" ]; then
  say "not Linux: nothing to relax"
  exit 0
fi

# Both knobs, not just the documented one. _unconfined gates whether an unconfined profile is
# subject to the restriction at all, so on an image where it is set the _userns knob alone reads
# as applied and changes nothing.
for knob in kernel.apparmor_restrict_unprivileged_userns \
            kernel.apparmor_restrict_unprivileged_unconfined; do
  current="$(sysctl -n "$knob" 2>/dev/null)" || { say "${knob}: absent"; continue; }
  if [ "$current" = "0" ]; then
    say "${knob}: already 0"
  else
    sudo sysctl -w "${knob}=0" >/dev/null 2>&1 \
      && say "${knob}: ${current} -> $(sysctl -n "$knob" 2>/dev/null)" \
      || say "${knob}: ${current}, could not change"
  fi
done

say "apparmor profile of this shell: $(cat /proc/self/attr/apparmor/current 2>/dev/null || echo unknown)"
say "user.max_user_namespaces: $(sysctl -n user.max_user_namespaces 2>/dev/null || echo unknown)"

# Ask the host directly whether a user namespace can be made inside a user namespace, which is
# what apply-seccomp does. Deliberately NOT a hand-rolled setgroups write: that fails on a
# perfectly healthy host too, because the inner process is unmapped and /proc still shows the
# outer owner, so it would report a problem that is not there.
if unshare -Urm sh -c 'unshare -Urm true' 2>/dev/null; then
  say "nested userns: OK"
else
  say "nested userns: REFUSED (srt and claude-sandbox cannot engage here)"
fi
say "capabilities in a nested userns: $(unshare -Urm sh -c 'unshare -Ur sh -c "grep -m1 CapEff /proc/self/status"' 2>/dev/null || echo unavailable)"
sudo aa-status --json 2>/dev/null | head -c 200 || say "aa-status: unavailable"
echo

# Facts apply-seccomp depends on, printed because two rounds of guessing at them cost more than
# one round of measuring: it creates a nested user+PID+mount namespace and remounts /proc, so the
# caller's identity, bubblewrap's version and how /proc is mounted are the remaining variables.
say "id: $(id -u):$(id -g) ($(id -un))"
say "bwrap: $(command -v bwrap >/dev/null && bwrap --version 2>&1 || echo absent)"
say "/proc mount: $(awk '$2=="/proc"{print $3" "$4; exit}' /proc/self/mounts 2>/dev/null)"
say "CapBnd: $(grep -m1 CapBnd /proc/self/status 2>/dev/null | awk '{print $2}')"
say "nested user+pid+mount ns: $(unshare -Urmp --mount-proc sh -c 'echo OK' 2>&1 | tail -1)"
say "kernel: $(uname -r)"
say "uid_map: $(tr -s ' ' < /proc/self/uid_map | xargs)"
say "already in a userns: $([ "$(tr -s ' ' < /proc/self/uid_map | xargs)" = "0 0 4294967295" ] && echo no || echo YES)"
say "seccomp mode of this shell: $(grep -m1 Seccomp: /proc/self/status | awk '{print $2}')"

