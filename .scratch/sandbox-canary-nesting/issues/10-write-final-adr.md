Type: task
Status: resolved

Blocked by: 07, 08, 09

## Question

Consolidate every resolved ticket on this map into the destination
artifact: a new `docs/adr/000X-...md` covering the canary-nesting model,
why the previous five-runtime methodology was broken, the per-runtime
default-posture decisions, the plumbing approach for each, and the scope
call on agent-specific harnesses — plus updating
`docs/reporting-site-plan.md` and cross-linking the
[seed-ipc-targets ADR](../seed-ipc-targets/issues/10-write-final-adr.md)
(whichever lands second should reference the first, since they compose:
seed-ipc-targets decides *what* gets seeded, this map decides whether the
sandboxed run can *reach* it).

## Answer

**Landed** as
[`docs/adr/0003-canary-nesting-and-the-comparability-criterion.md`](../../../docs/adr/0003-canary-nesting-and-the-comparability-criterion.md),
with the per-runtime, flag-audit and agent-harness findings landed alongside it
as [`docs/nesting-evidence.md`](../../../docs/nesting-evidence.md) — so no
`research/*` branch is needed to follow any verdict on this map. The ADR
references the seed-ipc-targets ADR (ADR 0002, which stayed with the probe at
the split); the matching one-line back-reference in that ADR is a follow-up in
the probe repository.

Descoped from this ticket: `docs/reporting-site-plan.md` is updated by the
matrix-shape tickets that actually remove the rows, not here.
