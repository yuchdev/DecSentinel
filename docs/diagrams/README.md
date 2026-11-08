# Diagrams

PlantUML component diagrams of the as-built DocSentinel package (`src/docsentinel/`).
Each `.puml` source sits beside its rendered `.svg` and `.png`. Re-render with
`python .claude/skills/plantuml/scripts/convert_puml.py <file>.puml --format svg`.

## Overview

![DocSentinel component overview: consumers, core, detectors, reporting, inputs and extras](component-overview.svg)

## Detectors by profile

![Detectors grouped by profile with the shared Markdown scanner, lazy standard loader and deep gate](component-detectors.svg)

## Reporting and telemetry

![Reporting shim and the telemetry package: loader, model, engine, extensions and templates](component-reporting.svg)

## Files

| Source | Rendered |
| --- | --- |
| `component-overview.puml` | `component-overview.svg`, `component-overview.png` |
| `component-detectors.puml` | `component-detectors.svg`, `component-detectors.png` |
| `component-reporting.puml` | `component-reporting.svg`, `component-reporting.png` |
