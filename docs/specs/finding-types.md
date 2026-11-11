# Finding Types — the DocSentinel finding standard

**Status:** Proposed (2026-11-11), pending owner sign-off.
**Scope:** every finding any rule emits: its type label, message shape, severity and
fault class, and how the text report prints it.
**Single source:** this document is the standard. `src/docsentinel/finding_types.py`
(to be added) mirrors the catalogue row for row, and a test fails if the two drift (the
same pattern as [`fault-classes.md`](/docs/specs/fault-classes.md) and
`FAULT_CLASSES`).

## 1. Finding fields

| Field | Meaning | Notes |
|---|---|---|
| `rule` | Rule code, `DSnnn` | From the rule registry. |
| `type` | **Type label**: what is wrong, in a few lowercase words | Exactly one row in §4. Never empty. |
| `value` | The offending token: a link target, path, label, identifier or name | Untrusted. Bounded, `unicode_escape`d and never a content snippet, except where §4 says otherwise (DS102, DS202, DS203). |
| `detail` | Optional extra facts: a threshold, a suggestion, where the token is declared | Untrusted. One short clause. |
| `severity` | `error` (blocking) or `warning` | The default is in §4; policy options may change it. |
| `line`, `column` | One-based position of the offending token | `column` counts code points. Either may be absent. |

The fault class (telemetry vocabulary) is per rule, from the
[rule-code to fault-class mapping](/docs/specs/fault-classes.md). The type
label is the reader-facing vocabulary, and a rule may have several types.

## 2. Message grammar

The `message` is derived from the fields, never written freely:

```
message = type [" -> " value] ["; " detail]
```

For example:
- `dangling link -> ./gone.md`
- `duplicate document id -> alpha; already declared in a.md`
- `missing fence language`

The message is part of the baseline fingerprint, so changing a type label, or the
value or detail shape, re-keys existing baselines. That counts as a breaking change:
record it in this file's changelog (§6) and regenerate the repository baselines in the
same change.

## 3. Text report rendering

```
<document path> (<bytes> bytes)
  <severity> <rule> <type>[, line <n>[, col <n>]][: <value>][; <detail>]
```

- The document path is printed once, on its header line, never on each finding line.
- Positions are labelled (`line 15, col 39`), never bare numbers.
- Severity is padded to 7 characters, so rule codes line up.
- The trailing `Blocking findings: N` recap spans documents, so it puts the path back:
  `  <severity> <rule> <type>: <path>[, line <n>[, col <n>]][: <value>][; <detail>]`.

For example:

```
adr/0002-dag-capable-stage-registry.md (17280 bytes)
  warning DS103 unresolvable path, line 15, col 39: docs/architecture/pipeline.md
  error   DS101 dangling link, line 22, col 3: ./gone.md

Blocking findings: 1
  error   DS101 dangling link: adr/0002-dag-capable-stage-registry.md, line 22, col 3: ./gone.md
```

`github` and JSON reports carry `type`, `value` and `detail` as separate fields, plus
`message`.

## 4. Catalogue

Severity is the rule default. "opt" marks an opt-in policy rule (inert until its option
is set). The **Was** column records the free-form message each type replaces, so the
migration can be traced.

### Fast profile

| Rule | Type label | `value` | `detail` | Sev | Was |
|---|---|---|---|---|---|
| DS101 | `dangling link` | link target | — | error | `dangling link -> T` |
| DS101 | `dangling anchor` | `#anchor` or `file#anchor` | — | error | `missing anchor 'a' in F` |
| DS102 | `stray html comment` | comment start, at most 80 chars | — | warning | `stray HTML comment: '…'` |
| DS103 | `unresolvable path` | path in a code span | — | warning | `unresolvable path -> P` |
| DS104 | `duplicate explicit anchor` | anchor | — | warning | `explicit anchor 'a' is defined more than once in this document` |
| DS104 | `anchor collision` | anchor | `collides with a generated heading anchor` | warning | `explicit anchor 'a' collides with the generated anchor of a heading` |
| DS105 | `heading level skip` | `level 4 after level 2` | — | warning | `heading level 4 skips a level after level 2` |
| DS105 | `wrong first heading level` | `level 3` | `expected level 1` | warning | `first heading is level 3; document should begin at level 1` |
| DS105 | `multiple top-level headings` | heading text | — | warning | (`multiple_h1_policy`) |
| DS106 | `empty section` | heading text | — | warning | `empty section: 'X' has no visible content` |
| DS108 | `undefined reference label` | label | — | warning | `undefined reference label: L` |
| DS108 | `duplicate reference definition` | label | — | warning | `duplicate reference definition: L` |
| DS108 | `unused reference definition` | label | — | warning | `unused reference definition: L` |
| DS109 | `unclosed code fence` | fence marker | `opened at line N; no matching closing delimiter` | error | `unclosed backtick fenced code block opened at line N: …` |
| DS109 | `malformed fence opener` | info string | `backtick fence info string may not contain a backtick` | error | `malformed opener: …` |
| DS109 | `stray closing fence` | fence marker | — | error | (`report_stray_closing_fence`) |
| DS110 opt | `missing fence language` | — | — | warning | `fenced code block has no language label` |
| DS110 opt | `disallowed fence language` | language | `not in allowed_fence_languages` | warning | `fence language 'x' is not in the configured allowlist` |
| DS112 opt | `duplicate navigation target` | target | — | warning | `navigation target is linked more than once` |
| DS112 opt | `missing navigation target` | target | — | warning | `navigation target does not exist` |
| DS112 opt | `navigation target outside root` | target | — | warning | `navigation target escapes the documentation root` |
| DS112 opt | `unlisted required document` | document | — | warning | `required navigation target is not listed …` |
| DS113 | `missing asset` | asset reference | — | error | `missing asset: P` |
| DS114 | `duplicate document id` | id | `already declared in F` | error | `duplicate document id "x" (already declared in F)` |
| DS114 | `missing document id` | field name | — | error | `document declares no "id" identity` |
| DS114 | `unsupported document id value` | field name | `not evaluated for uniqueness` | error | `document id field "id" has an unsupported value shape …` |
| DS115 opt | `deprecated reference` | old token | `replace with 'new' (<kind>, <mapping>)` | warning | `deprecated <kind> 'old' should be replaced …` |
| DS116 | `root escape` | target | — | error | `reference escapes the documentation root: T` |
| DS116 | `windows drive path` | target | — | error | `reference uses a Windows drive-letter path: T` |
| DS116 | `unc path` | target | — | error | `reference uses a UNC network path: T` |
| DS116 | `backslash separator` | target | — | error | `reference uses backslash path separators: T` |
| DS116 | `encoded separator` | target | `still encoded after one decode` | error | `reference keeps percent-encoded path separators after one decode: T` |
| DS116 | `control characters in reference` | target | — | error | `reference contains control characters: T` |
| DS117 | `table cell count mismatch` | `3 cells` | `header declares 2` | warning | `table body row has 3 cells; the header declares 2` |
| DS117 | `table delimiter cell count mismatch` | `3 cells` | `header declares 2` | warning | `table delimiter row has 3 cells; …` |
| DS117 | `malformed table alignment` | marker | — | warning | `table delimiter row has a malformed alignment marker: 'x'` |
| DS118 opt | `file naming violation` | file name | `<style>; suggested rename 'x'` | warning | `file name 'X' does not match the kebab naming policy; …` |
| DS118 opt | `directory naming violation` | directory name | `<style>; suggested rename 'x'` | warning | `directory name 'X' does not match …` |

### Standard profile

| Rule | Type label | `value` | `detail` | Sev | Was |
|---|---|---|---|---|---|
| DS201 | `readability grade too high` | grade, e.g. `19.2` | `max_grade_level 18.0` | warning | `Readability grade level 19.2 exceeds threshold 18.0` |
| DS202 | `near-duplicate text` | other location `a.md#chunk3` | `cosine 0.93: '<snippet>'` | warning | `near-duplicate of a.md#chunk3 (cosine 0.93): '…'` |
| DS203 | `low-information paragraph` | `'<snippet>'` | `score 0.12 < 0.30` | warning | `low-information paragraph (score …): '…'` |
| DS204 | `docstring signature mismatch` | function name | `SIGnnn <description> (<slug>)` | error | `f: SIGnnn … (slug)` |

### Deep profile (advisory)

| Rule | Type label | `value` | `detail` | Sev | Was |
|---|---|---|---|---|---|
| DS301 | `candidate contradiction` | subject | `'x' in A but 'y' in B; review to confirm` | warning | `candidate contradiction: subject …` |

## 5. Rules for changing this standard

1. A new finding kind needs a new row here **before** code emits it. The drift test
   fails on any emitted `(rule, type)` pair without a row.
2. Type labels are lowercase words, unique across all rules, with no trailing
   punctuation, and say what is wrong, not which check found it.
3. Renaming a label re-keys baselines (§2): add a changelog entry and regenerate the
   repository baselines in the same change.
4. `value` never carries document content, except the snippet-bearing types marked in
   §1, which stay bounded and escaped.

## 6. Changelog

- 2026-11-11: Proposed. It replaces free-form messages; only DS101–DS103 set `type`
  before this.
