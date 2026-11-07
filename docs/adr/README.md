# Architecture Decision Records

ADRs for DocSentinel use the [MADR](https://adr.github.io/madr/) (Markdown Any Decision Records) template.
Each record lives in this directory as `000N-slug.md`. Mermaid diagrams referenced by ADRs
are in `assets/`.

## Inventory

| ADR                                                            | Title                                             | Status   | Date       |
|------------------------------------------------------------------|----------------------------------------------------|----------|------------|
| [0001](0001-config-loading-via-layered-settings.md) *(example - delete once you have a real ADR)* | Config Loading via Layered pydantic-settings Sources | Accepted | 2026-01-15 |
| [0002](0002-fault-telemetry-event-emission.md) | Fault-Telemetry Event Emission via a Written Contract and Pluggable Sinks | Accepted | 2026-10-26 |
| [0003](0003-template-driven-reporting-on-telemetry.md) | Template-Driven Reporting Built on a Telemetry Package | Proposed | 2026-10-30 |

## Example ADR (delete before this project ships)

[`0001-config-loading-via-layered-settings.md`](0001-config-loading-via-layered-settings.md)
is a complete, fully-worked ADR - not a stub - shipped so `app-architect` and `/adr-write`
have something real to read for depth and structure before this project has written its
own first record. Its diagram, [`assets/0001-config-source-precedence.mmd`](assets/0001-config-source-precedence.mmd),
is the matching example of when an ADR is worth a Mermaid diagram and how much detail
belongs in one.

**Delete both files once this project has written its own first real ADR.** A stale
illustrative decision left in place afterward can be cited as prior art by mistake, or
get chained into a real ADR's `Supersedes` link. Your first real ADR landing as `0002`
(leaving a gap at `0001`) is expected and fine - see Naming conventions below.

## Template

Use `template.md` when creating a new ADR:

```bash
cp docs/adr/template.md docs/adr/0002-short-title.md
```

Replace the template placeholders with the record's number, title, date, and status.

## Naming conventions

- Filename: `000N-kebab-slug.md` - sequential, zero-padded to four digits.
- Status values: `Proposed` | `Accepted` | `Implemented` | `Superseded` | `Deprecated`.
- Superseded ADRs keep their file; add a `Superseded by: [000N](...)` line to their header.
