# Signature Bundle

This folder contains external scan-engine content that can ship separately from the core agent binaries.

The default bundle format is `default-signatures.tsv` with one rule per line:

`scope|code|message|tacticId|techniqueId|score|pattern1;pattern2;pattern3`

An optional eighth column, `match`, says how many of the patterns must appear: `all`, or a number. Without it, any one
pattern is enough (the patterns are alternatives). Rules that describe a chain or family of markers must set it: a
single common marker on its own (for example `WriteProcessMemory`, which browsers and updaters import) is not evidence
of ransomware. Agents older than this column ignore it.

The installer ships every file in this folder: `default-signatures.tsv`, `default-signatures-malicious.tsv`,
`default-signatures-observe.tsv`, and the trusted-publisher, known-good hash and observe-only lists the scan engine
uses to dampen verdicts on signed software.

Supported scopes:

- `any`
- `text`
- `ascii`
- `script`
- `pe`
- `zip`
- `ole`
- `lnk`
- `office`

How it is used:

- The scan engine first applies its built-in heuristics.
- It then loads `signatures\default-signatures.tsv` from the installed release layout, or from `ANTIVIRUS_SIGNATURE_BUNDLE_PATH` if that environment variable is set.
- Missing signature content is non-fatal; the engine falls back to compiled heuristics.

This gives the updater a clean path to ship new detection content without replacing the whole agent binary.