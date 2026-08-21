# Profile attestation (+ repo split)

wayfinder:map

> This map originally covered two coupled decisions charted together in
> `sandbox-probe` because the second motivated the first. The first —
> whether/how to split the comparison layer out of `sandbox-probe` — is
> resolved and executed; its tickets (01–04, 06) stay recorded in the probe
> repository's copy of this map:
> [controlplaneio/sandbox-probe `.scratch/profile-attestation/map.md`](https://github.com/controlplaneio/sandbox-probe/blob/main/.scratch/profile-attestation/map.md).
> This copy carries ticket 05 onward — the comparison-side half, the
> profile-attestation capability itself — which is why numbering starts at
> 05 rather than 01.

## Destination

A new "profile attestation" capability: given a declared, versioned,
externally-authored sandbox profile — starting with nono's registry packs
(e.g. `nolabs-ai/codex`) — run
`sandbox-probe` under that profile and diff the *empirically observed*
reachable surface against the profile's *declared* grants. Surfaces two new
finding classes the project doesn't have today: **declared-but-unreachable**
(the profile overclaims) and **reachable-but-undeclared** (the profile has a
real gap). This is the regression test nono profiles don't currently have.

## Why this map exists (how it was found)

Working [sandbox-canary-nesting](../sandbox-canary-nesting/map.md)'s ticket
08, Chris pushed back hard on the premise: for the 5 generic `sandbox`-family
runtimes (`docker`/`podman`/`bwrap`/`nspawn`/`gvisor`, no agent driving them),
*any* mount/sharing flags the project's own script adds are **our own
choice**, not a vendor's — testing "did the sandbox block what we chose to
expose" is circular regardless of which flags get picked. The comparisons
that are actually meaningful are the ones where *someone else* — an agent
vendor (Claude Code choosing its own Seatbelt config, confirmed in
[ticket 11](../sandbox-canary-nesting/issues/11-claude-sandbox-nesting.md)/
[12](../sandbox-canary-nesting/issues/12-codex-sandbox-nesting.md)) or a
declared policy — made the configuration decision, and we're observing it.

That reframing surfaced two things, both recorded on the probe-side copy of
this map: the project had been conflating a fingerprinting probe with a
comparison/benchmarking harness (the trigger for the repo split), and nono
itself already has exactly the missing "someone else made a real decision"
case — its registry ships signed, schema-valid, versioned profiles per agent
— but those profiles ship with **zero runtime behavioral verification**.
Sigstore signing proves provenance; schema validation proves the JSON is
well-formed; nothing proves the declared grants match what actually happens
when the profile runs.

## Notes

- Domain: see [CONTEXT.md](../../CONTEXT.md) — new vocabulary this map will
  need (candidates: "declared profile", "attestation", "drift" — declared vs
  actual mismatch) is not yet added; don't invent the final names without a
  domain-modeling pass once the mechanism ticket resolves.
- Standing preference: **plan, don't do** — same as both sibling maps.
- Relationship to sibling maps:
  - [sandbox-canary-nesting](../sandbox-canary-nesting/map.md): its
    agent-driven tickets (11–14) stay valid untouched. Ticket 08's "fix the 5
    generic runtimes' mount flags" is retired by this map's finding — see
    that map's own updated Notes.
  - [seed-ipc-targets](../seed-ipc-targets/map.md): stays relevant regardless
    of methodology — sockets/pipes/processes still need seeding. Its
    mechanism-design ticket should account for serving *both*
    baseline-vs-sandbox and declared-vs-actual comparisons once this map's
    shape is clearer.

## Decisions so far

- [Nono row profile switch](issues/05-nono-row-profile-switch.md) — two new
  rows, not a switch: (1) `sandbox-probe` itself run under
  `nono run --profile nolabs-ai/codex`, diffed against declared grants — the
  flagship attestation capability; (2) real `codex` CLI run under the same
  profile (`codex-nono`), alongside `codex-sandbox`, using existing
  methodology unchanged. Existing generic `nono` row stays (legitimate
  hand-authored-policy pattern, not circular). Confirmation was hedged ("i
  think so") — flagged for revisiting once there's something concrete to
  react to.

The prerequisite research (nono profile invocation, schema-to-findings
mapping, audit-command overlap) and the repo-split scoping itself are
resolved decisions recorded on the probe-side copy of this map, linked above.

## Not yet specified

- Exact mapping from nono's `Profile`/`CapabilitySet` schema fields to
  `sandbox-probe`'s finding types — see the probe-side copy of this map for
  the research ticket this depends on.
- Whether other declarative profile systems (beyond nono) exist and are
  worth the same treatment — deferred until nono's own case is proven out.

## Out of scope

- Fixing the 5 generic runtimes' mount flags in `sandbox-canary-nesting`
  (docker/podman/bwrap/nspawn/gvisor with no agent, no declared profile) —
  ruled out by this map's core finding, not fog. See that map's ticket 08 for
  the formal closure.
