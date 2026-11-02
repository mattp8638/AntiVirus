# Fenrir Signature / Feed Database Import

This folder documents the Sentinel import boundary for reusable threat-feed and signature concepts from `zy538324/signaturedb-fenrir`.

## Source repository

- Source repo: `zy538324/signaturedb-fenrir`
- Useful source file: `src/feedService.ts`

## Reusable capabilities identified

The source feed service defines a strong model for:

- hash indicators
- URL indicators
- YARA rules
- Suricata rules
- ClamAV rules
- feed summary/status
- source status tracking
- deduplication by ID
- source tagging
- generated bundle versioning
- upstream sync concepts for MalwareBazaar, URLhaus and YARAify

## Sentinel integration decision

Sentinel is Python/FastAPI, so the TypeScript service is not copied directly. Instead, the schema and normalisation approach is imported into a Python-native module:

```text
modules/threat_feeds/router.py
```

This avoids running a second runtime just to use feed data.

## Future source mapping

The Python module should evolve to support:

- MalwareBazaar recent hashes
- URLhaus recent URLs
- URLhaus recent payload hashes
- YARAify YARA rules
- URLhaus Suricata rules
- optional ClamAV feed lines
- local JSON feed imports

## Consumers inside Sentinel

Threat feeds should power:

- IOC Scanner
- AV Bridge enrichment
- DNS Monitor
- DNS Protection Tool
- Phishing Email Analyser
- URL Redirect Tracer
- Attachment Risk Analyser
- Mini-SIEM / Log Search
- Alert Correlation Engine
