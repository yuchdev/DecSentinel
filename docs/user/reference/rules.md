# Rules — the single table of DocSentinel checks

This is the one table of every check DocSentinel runs. Other documents link here instead of
keeping their own rule tables.

- **Code is the reference.** Code, profile, severity, activation, title and "What it reports"
  repeat the `Rule` registration in each detector module (`/src/docsentinel/rules.py` holds the
  registry) word for word. They also match what `docsentinel rules` prints. The fault class repeats
  `FAULT_CLASSES` in `/src/docsentinel/telemetry/classify.py`.
- **A test enforces it.** `/tests/integration/test_rules_table.py` fails when a registered rule has
  no row here, a row has no rule, or any of the columns above differs from the code or the CLI
  listing. It also fails when a config key named here is not a `Config` field.
- **Adding or changing a rule** updates this table in the same change.

Activation `always` means the rule runs whenever its profile is selected. `opt-in` means it reports
nothing until the named option is set. Profiles are exact, not cumulative. The finding types each
rule emits are catalogued in [finding-types.md](../../specs/finding-types.md#4-catalogue). Options
are explained in the [Configuration Reference](configuration.md) and the
[Statistical Checks Reference](statistical-checks.md).

| Code | Profile | Severity | Activation | Title | What it reports | Fault class | Config keys |
|---|---|---|---|---|---|---|---|
| DS101 | fast | error | always | Dangling link or anchor | A Markdown link or #anchor target does not resolve. | `dangling_reference` | `link_root` |
| DS102 | fast | warning | always | Stray HTML comment | An HTML comment was left in rendered Markdown. | `residual_markup` | — |
| DS103 | fast | warning | always | Unresolvable path-like code span | An inline code span looks like a file path but does not resolve. | `unresolvable_path` | `link_root` |
| DS104 | fast | warning | always | Conflicting heading and explicit anchors | An explicit HTML anchor repeats another explicit anchor or shadows a generated heading anchor. | `identifier_collision` | `anchor_collision_policy`, `anchor_renderer` |
| DS105 | fast | warning | always | Heading hierarchy and section levels | A heading skips a level or the first heading is deeper than the configured root level. | `structure_violation` | `heading_level_policy`, `first_heading_level`, `multiple_h1_policy`, `setext_heading_support` |
| DS106 | fast | warning | always | Empty or contentless sections | A heading introduces a section with no visible, publishable content. | `empty_content` | `empty_section_policy`, `placeholder_content_policy`, `image_content_counts`, `empty_section_min_text_chars` |
| DS108 | fast | warning | always | Reference-style link definition integrity | A reference-style link uses an undefined label or a label is defined more than once. | `reference_integrity` | `unused_reference_definitions`, `duplicate_reference_definitions`, `reference_label_normalization` |
| DS109 | fast | error | always | Malformed or unclosed fenced code blocks | A fenced code block has no valid closing delimiter or a malformed opener. | `fence_violation` | `fence_dialect`, `report_stray_closing_fence` |
| DS110 | fast | warning | opt-in: `require_fence_languages` | Missing language labels on code fences | A meaningful fenced code block omits the language label required by policy. | `fence_language_missing` | `require_fence_languages`, `allow_unlabelled_empty_fences`, `allowed_fence_languages`, `fence_dialect` |
| DS112 | fast | warning | opt-in: `navigation_indexes` | Declared documentation navigation integrity | A configured navigation index omits a required target, links a target more than once, or points at a missing or escaping local destination. | `navigation_integrity` | `navigation_indexes`, `navigation_required`, `navigation_unique_targets`, `navigation_check_missing`, `link_root` |
| DS113 | fast | error | always | Missing local media and document assets | A local media or document asset referenced by the docs does not exist as a regular file. | `missing_asset` | `asset_extensions`, `check_html_asset_tags`, `check_markdown_images`, `check_srcset`, `missing_asset_policy`, `link_root` |
| DS114 | fast | error | always | Duplicate stable document identifiers | Two documents declare the same stable frontmatter identity within the configured scope. | `duplicate_identity` | `document_id_field`, `document_id_scope`, `document_id_case_sensitive`, `document_id_required` |
| DS115 | fast | warning | opt-in: `deprecated_references_file` | Deprecated names and migrated references | A document uses a name or reference explicitly mapped as deprecated in the configured deprecated-references mapping file. | `deprecated_reference` | `deprecated_references_file`, `deprecated_check_prose`, `deprecated_check_links`, `deprecated_case_sensitive` |
| DS116 | fast | error | always | Path traversal outside documentation root | A documentation reference escapes the configured scan root. | `path_escape` | `root_escape_policy`, `decode_percent_paths`, `windows_path_policy`, `link_root` |
| DS117 | fast | warning | always | Malformed GFM pipe-table structure | A pipe table has inconsistent cell counts or malformed alignment markers. | `table_malformed` | `table_dialect`, `table_strict_cells`, `table_enable` |
| DS118 | fast | warning | opt-in: `documentation_naming` | Documentation file and directory naming policy | A documentation file or directory name does not match the configured portable naming policy (documentation_naming). | `naming_policy` | `documentation_naming`, `documentation_naming_allow`, `documentation_naming_directories`, `documentation_naming_prefix_patterns` |
| DS201 | standard | warning | always | High text complexity | Document readability grade level exceeds the configured threshold. | `high_complexity` | `max_grade_level`, `min_document_words` |
| DS202 | standard | warning | always | Duplicated text or facts | A paragraph is a near-duplicate of another paragraph in the corpus. | `duplicate_text` | `duplicate_similarity`, `min_paragraph_words`, `min_paragraph_chars` |
| DS203 | standard | warning | always | Low-information content | A paragraph is both lexically thin and non-distinctive. | `low_information` | `min_information_score`, `min_paragraph_words`, `min_paragraph_chars` |
| DS204 | standard | error | always | Docstring/signature mismatch | A function docstring's documented parameters or returns do not match its signature. | `contract_mismatch` | `docsig_paths` |
| DS301 | deep | warning | always | Fact-contradiction candidate | Two documents make differing numeric or named-entity claims about the same subject. | `contradiction_candidate` | `deep_confirm` |

## Profiles at a glance

- **fast** (default): `DS101`–`DS118`, standard library only at scan time.
- **standard**: `DS201`–`DS204`, needs `docsentinel[standard]`.
- **deep**: `DS301`, needs `docsentinel[deep]` and explicit confirmation. Advisory only, so it never
  fails a scan.

The codes `DS107`, `DS111` and `DS119`–`DS123` are specified in
[Milestone 0004](../../roadmap/0004-deepening-test-cases/plan.md) but not implemented. They have no
row here until a detector registers them.
