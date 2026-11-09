# Markdown Scanner Developer Guide

This guide explains how DocSentinel's shared `markdown_blocks.py` scanner works,
how resolvers and detectors divide responsibility, and what you must do when adding
a new rule.

See also:
- [docs/dev/markdown_dialect.md](markdown_dialect.md) — Supported dialect, intentional gaps,
  known false positives and negatives for each rule.
- [docs/user/reference/configuration.md](../user/reference/configuration.md) — Every config
  option and its default.
- [docs/architecture/README.md](../architecture/README.md) — High-level engine and profile
  boundaries.

---

## Scanner architecture

`src/docsentinel/markdown_blocks.py` is the single, standard-library-only Markdown
scanner used by all fast-profile detectors (DS104–DS118). It is **not** a full
CommonMark or GFM implementation; it recognizes a narrow, explicitly enumerated subset
of GitHub Flavored Markdown. See `docs/dev/markdown_dialect.md` for the complete list
of supported and unsupported constructs.

### Scan entry point

```python
from docsentinel.markdown_blocks import scan_markdown, MarkdownBlockIndex

index: MarkdownBlockIndex = scan_markdown(text: str)
```

`scan_markdown` returns a frozen `MarkdownBlockIndex` that holds all tokenized
constructs. The index is the single source of truth for a document's parsed
structure; detectors should never parse the raw text again.

### Tokens and fields

`MarkdownBlockIndex` exposes these attributes (all are read-only):

| Attribute | Type | Contents |
|-----------|------|----------|
| `headings` | `tuple[Heading, ...]` | ATX and setext headings with level, text, slug, line |
| `fences` | `tuple[Fence, ...]` | Fenced code blocks with marker, info, `closed`, line range |
| `inline_code` | `tuple[InlineCode, ...]` | Single-line backtick spans |
| `links` | `tuple[LocalReference, ...]` | Inline links and image sources (local targets only) |
| `reference_definitions` | `dict[str, ReferenceDefinition]` | Label → definition |
| `reference_uses` | `tuple[ReferenceUse, ...]` | Full and collapsed reference uses |
| `explicit_anchors` | `tuple[HtmlAnchor, ...]` | `<a id="...">` and `<a name="...">` tags |
| `html_anchors()` | method | Set of all anchor ids/names (headings + explicit) |
| `anchor_names()` | method | Same as `html_anchors()`, used by DS101 |
| `table_rows` | `tuple[TableRow, ...]` | Pipe-table rows (header, delimiter, body) |
| `images` | `tuple[Image, ...]` | Markdown images (`![alt](src)`) |
| `html_images` | `tuple[HtmlImage, ...]` | HTML `<img>`/`<source>` tags |
| `html_links` | `tuple[HtmlLink, ...]` | HTML `<a href>` tags |
| `comments` | `tuple[Comment, ...]` | HTML comment ranges |

Helper methods:

- `fenced_line_numbers()` — returns the set of one-based line numbers inside
  any fence (including unclosed fences). Used as a mask by DS106, DS109, DS110,
  DS117.
- `split_physical_lines(text)` — shared physical-line splitter (handles LF,
  CRLF, lone CR); used by DS105 and DS108 to align line numbering with the index.

### Masking order

Detectors that must ignore content inside fences, inline code, or HTML comments
apply masks in this order:

1. **Fences** — `fenced_line_numbers()` or the `Fence` offset ranges.
2. **Inline code** — `InlineCode` offset ranges.
3. **HTML comments** — `Comment` offset ranges.

This order matches CommonMark: fences suppress everything inside, then inline
code, then comments. A construct is never tokenized inside a fence; inline code
is never tokenized inside another inline code span; and comments are never
tokenized inside inline code.

DS108 and DS112 derive their own masked view by blanking these regions from the
physical lines before parsing their respective constructs (reference definitions
and navigation list items).

---

## Resolver ownership

`resolve_local_reference(root, document_path, raw_target, *, link_root=None)` in
`markdown_blocks.py` is the **only** path resolver in the fast profile. It is purely
lexical: it never opens a file, follows a symlink, or makes any filesystem call.
A root-relative target (leading `/`) is joined onto `link_root` (the
`link_root` option, resolved and bounded by the nearest `.git` ancestor once per scan by the engine with `docsentinel.link_root.resolve_link_root` and passed to detectors as `link_root=`; a detector without it falls back to the lexical `link_root_for`, which accepts only values meaning the scan root;
`None` means the scan root) and its `..` is bounded by it. The result's `boundary`
field names the root to use for symlink containment.

The resolver classifies a target as one of:

| Outcome | Meaning |
|---------|---------|
| `RESOLVED` | A valid relative or root-relative path (may or may not exist on disk) |
| `EXTERNAL` | An absolute URL (`http://`, `https://`, `mailto:`, etc.) |
| `OUTSIDE_ROOT` | A lexical path that escapes the root (e.g. `../../etc/passwd`) |
| `UNSUPPORTED` | A target the scanner cannot handle safely (drive letter, UNC, backslash, control byte, template `${...}`, glob `*?[`) |

The `ResolvedReference.reason` field carries a typed sub-category for
`UNSUPPORTED` targets: `drive`, `unc`, `backslash`, `control`, `template`,
`glob`. DS116 uses this field to separate unsafe references (which it reports)
from safe unsupported ones (template/glob, which it ignores).

### Who resolves what

| Rule | Resolver usage |
|------|----------------|
| DS101 | Calls the resolver for every link, image, and reference-definition target. Delegates all `UNSUPPORTED` targets to DS116 via `is_ds116_owned`; never stats an unsafe target. |
| DS103 | Legacy resolver for inline code spans only. Per the Story 11.0 code-span ruling, DS103 does **not** call `is_ds116_owned`; it skips only genuine root-escape and symlink-out code spans (via `escapes_via_symlink`) and retains its pre-Story-11 behaviour for drive/UNC/backslash/control code spans. |
| DS112 | Calls the resolver for navigation link targets. Delegates `OUTSIDE_ROOT` and `UNSUPPORTED` targets to a DS116 finding (zero filesystem access). |
| DS113 | Calls the resolver for image/asset targets. Defers `OUTSIDE_ROOT` and `is_ds116_owned` targets entirely to DS116; never stats outside the root. |
| DS116 | Owns all `OUTSIDE_ROOT` and unsafe `UNSUPPORTED` references. For inline code spans, reports only genuine traversal (root escape or in-root symlink-out); leaves drive/UNC/backslash/control code spans to DS103. |

**Never add a second path resolver.** If a detector needs to know whether a
target is safe, call `is_ds116_owned(resolved_ref)` from `path_boundaries.py`
and delegate to DS116.

---

## Config forwarding

The engine calls every analyzer as one of:

```python
detect(root, documents)                # two-argument (legacy) form
detect(root, documents, config)        # three-argument form
detect(root, documents, *, config)     # keyword-only `config` form
```

The engine introspects the analyzer's signature; if it accepts a third `config`
parameter (positional or keyword-only), the effective `Config` object is passed.
Two-argument analyzers receive only `root` and `documents`.

When writing a new detector that needs config options, declare:

```python
def detect(
    root: Path,
    documents: tuple[Document, ...],
    config: Config,
) -> tuple[Finding, ...]:
    ...
```

### Injected Config and load_config validation

`load_config` validates every option (enum vocabularies, integer ranges, path
containment, allowlist formats) before constructing a `Config`. A `Config`
constructed directly in Python code bypasses that validation. Detectors that
open files or use path options must therefore **re-validate defensively** at the
point they use the value, not assume it was checked by `load_config`.

DS115 demonstrates this pattern: before opening `deprecated_references_file` it
re-runs `is_ds116_owned` + `escapes_via_symlink` + `os.stat` + `S_ISREG` even
though `load_config` already rejected out-of-root paths — because a library
caller could have injected a `Config` with an arbitrary path.

---

## Adding a new rule

Follow these steps when adding a new fast-profile rule.

### 1. Registration

Register the rule once in `src/docsentinel/rules.py`:

```python
Rule(
    code="DS1NN",
    name="Short, readable rule name",
    profile="fast",
    severity="warning",  # or "error"
    # For an opt-in rule, name the Config option that enables it:
    opt_in_option="my_option_name",  # omit for always-active rules
)
```

Rules with `opt_in_option` are named in `ScanResult.notice` when their policy
is off, marked `[opt-in: set <option>]` in `docsentinel rules`, and counted
separately in `docsentinel doctor`. They are still in `enabled_rules`; selection
is orthogonal to whether the policy fires.

### 2. Detector module

Create `src/docsentinel/detectors/mydetector.py`. Import from the scanner:

```python
from docsentinel.markdown_blocks import scan_markdown
from docsentinel.rules import ANALYZERS, Rule

def detect(
    root: Path,
    documents: tuple,
    config,
) -> tuple:
    findings = []
    for doc in documents:
        index = scan_markdown(doc.text)
        # ... use index tokens ...
    return tuple(findings)

ANALYZERS["DS1NN"] = detect
```

Register the module in `src/docsentinel/detectors/__init__.py`.

### 3. Fixtures and manifest

Create at least 3 clean and 3 finding scenario directories under
`tests/assets/ds1nn/`. Add each scenario to `tests/milestone_0005_manifest.py`
(or the equivalent manifest for your milestone) so the registration-gated
catalog enforces them.

Run `uv run pytest tests/integration/test_milestone_0005_fixture_catalog.py`
to confirm the manifest counts match committed assets and rule registration.

### 4. Hardcoded-rule-list pitfalls

Some integration tests build expected rule sets as tuples or constants. When
you add a rule, search for `"DS1` (or your prefix) in the integration test
files and update any hardcoded lists; the test runner will catch most of these
with assertion failures on `enabled_rules` or `ScanResult.notice`.

---

## Security checklist for new detectors

Every new detector must pass the following checks before merging:

### Filesystem recorder

Wrap `os.stat`, `os.lstat`, `os.readlink`, `os.scandir`, `os.listdir`,
`open`, and `io.open` with a recording shim, then run the detector on a
hostile corpus containing:
- Symlinks pointing outside the scan root.
- Files with control bytes, `../` traversals, and percent-encoded separators
  in their names.
- A real file at `/etc/passwd` on the test machine.

Verify that zero calls reach outside the scan root. A call to `os.stat`
with an untrusted outside-root path leaks whether the file exists, regardless
of whether the result is used (information-disclosure, classified HIGH).

### Flood tests with shared-prefix shapes

For every loop or regex over document content, run a doubling series of at
least five sizes with the `assert_scales_linearly` helper from
`tests/timing_helpers.py`. Use **both**:
- Single-line floods (one very long line with N copies of the construct).
- Multi-line floods (N lines each with a short copy of the construct).

Reason: a single-line test hides per-line quadratics; a multi-line test
hides per-character quadratics inside a single line. Also test
shared-prefix shapes (many `old` tokens sharing a first token, for DS115)
and increasing-length patterns (backtick runs of length 1, 2, 3, …, for
any scanner that matches balanced delimiters).

The smallest size in the doubling series must cost at least **50 ms of CPU
time** on the vulnerable code path to ensure the timing guard discriminates;
a guard that passes vacuously (because the workload is too small) is no
guard at all. Validate the guard by injecting the known-bad implementation
and confirming it fails.

### Mutation checks

For each finding scenario in the fixture catalog, verify that removing or
neutering the detector turns the test red. At least five independent mutation
checks are required: disable the detector entirely, reverse a comparison,
drop a masking step, skip the opt-in gate, and (for file-reading rules)
replace the existence check with a trivially-passing stub.

### Bounded repr-escaped echo

Every `Finding.message` and every `ConfigError` message that includes
user-controlled text (file paths, labels, document content) must:
1. Truncate to a documented maximum (80 characters is the convention).
2. Apply `repr()` or `ascii()` (or equivalent) before embedding in the
   message so that ESC, NUL, CR, LF, and RTL-override characters cannot
   reach a terminal, CI annotation, or log unescaped.

Never echo a resolved absolute path or an existence oracle (whether a file
was found or not outside the root).

---

## Config precedence reference

| Source | Wins over |
|--------|-----------|
| `Config(...)` injected by a library caller | everything |
| `docsentinel.toml` at the scan root | `pyproject.toml` |
| `[tool.doc_sentinel]` in `pyproject.toml` | defaults |
| `Config` defaults | nothing |

When both `docsentinel.toml` and `pyproject.toml` are present, `docsentinel.toml`
wins entirely; `pyproject.toml` is not read.

### Incomplete-vs-clean status

The scan exit code and `ScanResult.notice` separately convey scan health
and rule status:

| Situation | Exit code | Notice |
|-----------|-----------|--------|
| No findings, all active rules evaluated | 0 | `"N fast rule(s) evaluated."` |
| Warnings only | 0 | `"N fast rule(s) evaluated."` |
| Errors (or warnings with `--strict`) | 1 | `"N fast rule(s) evaluated."` |
| Opt-in rules off | 0 or 1 | Names off opt-in rules: `"... opt-in rule(s) not enabled: DS110 ..."` |
| Readiness error (bad config, missing index) | 2 | CLI prints `Scan failed:` |
| Config load failure | 2 | CLI prints the `ConfigError` message |

An opt-in rule that is off is **not** counted in the evaluated total but is
explicitly named in the notice. A rule turned off by a policy option
(`root_escape_policy = "off"`, `table_enable = false`, etc.) is still counted
as evaluated because its gate is user-configured, not a project-level opt-in.
