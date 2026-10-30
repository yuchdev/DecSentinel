# Rule-code to fault-class mapping

Hand-maintained mapping consumed by the fault-telemetry adapter in
[`telemetry/`](telemetry/__init__.py) to set the `class` field of every emitted
`FaultEvent`. It lives next to [`rules.py`](rules.py) because it is co-maintained
with the rule registry: **every registered rule code must have exactly one row
here.** A rule that reaches the adapter with no row falls back to the generic
class `"unmapped"` - that fallback is a review failure, not a normal state.

See [ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md) for the event
schema, the `tier`/`outcome` vocabulary, and where emission happens, and
[the fault-event contract spec](/docs/specs/fault-event-contract.md) for the
cross-tool wire shape.

- `tier` is derived from the rule's profile, not stored here: `fast`/`standard`
  -> `deterministic`, `deep` -> `heuristic`.
- `class` is a free string shared across DocSentinel and FlakeForge (not a closed
  enum); keep names stable once published, since collectors aggregate on them.

## Fast profile (DS1xx) - deterministic

| Rule  | Profile | Fault class            | Notes |
|-------|---------|------------------------|-------|
| DS101 | fast    | `dangling_reference`   | Dangling links/anchors |
| DS102 | fast    | `residual_markup`      | Stray HTML comments |
| DS103 | fast    | `unresolvable_path`    | Unresolvable local paths |
| DS104 | fast    | `identifier_collision` | Conflicting heading/explicit anchors |
| DS105 | fast    | `structure_violation`  | Heading-hierarchy skips |
| DS106 | fast    | `empty_content`        | Contentless sections |
| DS108 | fast    | `reference_integrity`  | Undefined/duplicate reference definitions |
| DS109 | fast    | `fence_violation`      | Malformed/unclosed fenced code |
| DS110 | fast    | `fence_language_missing` | Missing code-fence language label (opt-in) |
| DS112 | fast    | `navigation_integrity` | Declared navigation integrity (opt-in) |
| DS113 | fast    | `missing_asset`        | Missing local media/document asset |
| DS114 | fast    | `duplicate_identity`   | Duplicate stable document identifier |
| DS115 | fast    | `deprecated_reference` | Deprecated name/migrated reference (opt-in) |
| DS116 | fast    | `path_escape`          | Reference escaping the scan root |
| DS117 | fast    | `table_malformed`      | Malformed GFM pipe table |
| DS118 | fast    | `naming_policy`        | File/directory naming policy (opt-in) |

## Standard profile (DS2xx) - deterministic

| Rule  | Profile  | Fault class         | Notes |
|-------|----------|---------------------|-------|
| DS201 | standard | `high_complexity`   | Text readability/complexity |
| DS202 | standard | `duplicate_text`    | Near-duplicate text |
| DS203 | standard | `low_information`   | Low-information content |
| DS204 | standard | `contract_mismatch` | Docstring-to-signature mismatch |

## Deep profile (DS3xx) - heuristic

| Rule  | Profile | Fault class              | Notes |
|-------|---------|--------------------------|-------|
| DS301 | deep    | `contradiction_candidate` | Semantic contradiction candidate (advisory-only) |

## Fault-mode aggregates these classes feed

- **fabricated-reference rate:** `dangling_reference` + `unresolvable_path` +
  `missing_asset` + `reference_integrity` + `path_escape`.
- **cross-model disagreement:** `contradiction_candidate`.
- **HITL escalation rate:** events with `outcome = "escalated"` (reserved; not
  emitted by DocSentinel v1).
