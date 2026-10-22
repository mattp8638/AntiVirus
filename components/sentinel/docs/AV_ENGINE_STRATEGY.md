# Sentinel / Fenrir AV Engine Strategy

## Decision

Sentinel must not rely permanently on the old `Palmertech-Webdev/AntiVirus` scanner as the core AV engine.

The existing C++ AV scanner is useful as a temporary compatibility bridge and as a source of prior detection logic, signatures and design lessons, but the Sentinel/Fenrir platform should have a purpose-built AV engine designed for this suite.

## Correct position

The current AV bridge is an interim adapter only.

It exists so Sentinel can:

- reuse earlier scanner work during MVP development
- invoke the existing Windows scanner where available
- parse scanner results into the new Sentinel UI
- avoid losing work already completed
- keep AV scanning available while the bespoke engine is built

It is not the final AV architecture.

## Final target

Build a new Fenrir AV engine that is:

- designed for the Sentinel agent model
- cross-platform where practical
- modular
- rule-driven
- evidence-aware
- safe by default
- compatible with investigation, case management and reporting
- capable of using local signatures, YARA rules and threat feeds
- able to run in scan-only mode or controlled remediation mode

## Recommended language split

| Component | Recommended approach |
|---|---|
| Sentinel backend orchestration | Python / FastAPI |
| Desktop/front-end shell | React now, Tauri later if desktop packaging is required |
| MVP endpoint agent | Python acceptable for speed |
| Production endpoint agent | Rust preferred |
| Bespoke AV engine | Rust preferred for new build; C++ legacy engine remains optional |
| Windows-specific low-level work | C++ or Rust with Windows APIs only when needed |
| Rules | YARA-compatible rules + Fenrir YAML/JSON metadata |
| Feeds | Local JSON bundles from Sentinel Threat Feed Aggregator |

## Why not depend on the old C++ AV permanently?

The old AV scanner is Windows-specific and was not originally designed as one module inside the Sentinel Blue Team platform.

Concerns:

- cross-platform limitations
- build/deployment complexity
- old GUI/control-plane assumptions
- not fully aligned with the new agent investigation workflow
- harder to integrate cleanly with cases, evidence bundles, health score and rule distribution
- potentially harder to maintain as the platform grows

## What should be reused from the old AV repo?

Reuse selectively:

- signature ideas
- scanner CLI behaviour lessons
- JSON output shape where useful
- quarantine/evidence concepts
- ATT&CK tagging ideas
- safe scan/remediation separation

Do not import as core architecture:

- old GUI
- old installer UI
- old control plane
- WebView assets
- generated binaries
- tightly-coupled Windows-only assumptions

## Bespoke AV MVP scope

The new AV module should start as a safe scanning engine, not a kernel-level product.

### MVP capabilities

- file hash calculation
- recursive file scanning
- extension and file type checks
- suspicious path checks
- entropy checks
- signature/rule matching
- YARA rule support where dependency is available
- embedded URL/IP extraction
- simple PE/script/document heuristics
- threat feed hash/URL matching
- JSON result output
- human-readable Sentinel UI output
- evidence attachment
- scan-only default mode
- quarantine only when explicitly enabled

### MVP outputs

Each finding should include:

- file path
- file type
- SHA256
- size
- matched rule/signature
- severity
- confidence
- ATT&CK mapping where available
- reason flagged
- recommended action
- remediation state
- evidence reference

## Bespoke AV architecture inside Sentinel

Proposed structure:

```text
modules/av_engine/
  __init__.py
  router.py
  scanner.py
  hashing.py
  filetypes.py
  entropy.py
  extractors.py
  rules.py
  yara_adapter.py
  feeds.py
  quarantine.py
  evidence.py
  models.py
```

Agent-side structure later:

```text
agent/
  collectors/
  av/
    scanner.py or rust scanner crate
    rules/
    quarantine/
    evidence/
```

## Role of the current AV bridge after bespoke engine exists

Once the bespoke engine is built, the bridge should become optional:

1. `native_fenrir` — default Sentinel-built AV engine.
2. `external_cli` — optional legacy Windows C++ scanner bridge.
3. `disabled` — AV scanning unavailable.

## Exit criteria for replacing the old scanner dependency

The bespoke AV engine is acceptable when:

1. Sentinel can scan a file and folder without the old C++ binary.
2. Findings are displayed in the AV Scanner tab as cards, not JSON.
3. Hash, file type, rule match, severity and recommended action are present.
4. Threat feed hash matching works.
5. YARA scanning works if YARA support is installed, and degrades cleanly if not.
6. Scan-only mode is the default.
7. Quarantine cannot happen accidentally.
8. Evidence metadata is stored.
9. Results can attach to an investigation/case.
10. The old C++ scanner can be removed and Sentinel still has AV scanning capability.

## Build order

1. Keep the current AV bridge as temporary compatibility.
2. Build `modules/av_engine` as a native Sentinel scanning engine.
3. Wire the AV Scanner UI to prefer native engine results.
4. Keep external CLI as an optional secondary engine.
5. Add agent-side native scanning.
6. Only then decide whether the old C++ AV repository should be archived, wrapped, or replaced.
