# Fenrir AV Windows Scanner Integration

This folder contains the Sentinel-side import boundary for the existing Windows AV scanner work from `Palmertech-Webdev/AntiVirus`.

The old AV project is useful, but it should not become the central Sentinel platform. Sentinel should treat it as an optional Windows scanning engine that can be invoked by agent/investigation workflows.

## Source repository

- Source repo: `Palmertech-Webdev/AntiVirus`
- Useful source path: `agent/windows/tools/scannercli`
- Useful build target: `antivirus-scannercli`
- Output binary name in the source project: `fenrir-scannercli.exe`

## Imported behaviour summary

The source scanner CLI is documented as a targeted local Windows scan utility. It can:

- scan explicit file and directory targets recursively
- output JSON
- simulate minifilter-style real-time operations with `--realtime-op`
- compute SHA-256 for suspicious files where possible
- flag risky executable and script extensions with ATT&CK context
- support scan exclusions
- quarantine files unless `--no-remediation` is used
- write local evidence records
- queue scan telemetry locally

## Sentinel integration decision

Sentinel must not copy the old GUI. The only AV-related components to bring into Sentinel are:

1. scanner CLI invocation boundary
2. scanner output parser
3. signature/rule seed data
4. optional evidence attachment into investigations
5. documentation for building/importing the Windows binary

The old AV engine remains Windows-specific. Sentinel should call it only when configured.

## Required local binary layout

For development, place the built binary at either:

```text
external/av/windows-scanner/bin/fenrir-scannercli.exe
```

or set:

```text
FENRIR_SCANNERCLI_PATH=C:\path\to\fenrir-scannercli.exe
```

## Sentinel API wrapper

The Sentinel backend wrapper is in:

```text
modules/av_bridge/router.py
```

It exposes safe targeted scan endpoints without importing the old AV GUI.

## What is intentionally not imported

The following are intentionally not imported directly into Sentinel at this stage:

- old frontend/console GUI
- installer GUI
- PAM UI
- minifilter driver payloads
- WebView2 assets
- full control-plane implementation
- generated build outputs

Those components can remain in the AV repository until there is a stable release packaging strategy.

## Future production decision

Long term, Sentinel can support three modes:

1. `disabled` — no AV engine configured.
2. `external_cli` — call the Windows scanner CLI and parse JSON.
3. `native_agent` — agent directly includes Rust/C++ scanning capability.

For now, `external_cli` is the correct MVP path.
