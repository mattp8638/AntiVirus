# Fenrir Topology Import

This folder documents the Sentinel import boundary for reusable topology discovery logic from `zy538324/Topology`.

## Source repository

- Source repo: `zy538324/Topology`
- Useful source file: `fenrir_topology.py`

## Reusable capabilities

The topology code provides useful defensive discovery primitives:

- default subnet detection
- default gateway detection
- ARP table parsing
- lightweight active host probing
- TCP port probing
- reverse DNS lookup
- simple HTTP server banner collection
- OUI/MAC vendor inference
- device role classification
- inferred gateway/subnet links
- optional SNMP/LLDP enrichment hooks
- topology findings for weak evidence or exposed SNMP

## Sentinel integration decision

Sentinel should not import the old standalone web server/GUI. Instead, Sentinel should expose topology collection as a backend module and render results in the main Sentinel UI.

The active Sentinel wrapper is:

```text
modules/topology/router.py
```

## Safety boundaries

Topology scanning must be limited to authorised networks only.

Default limits:

- no subnet larger than /20
- no aggressive scanning
- TCP connect checks only
- SNMP communities are optional and must be explicitly supplied
- results are stored as evidence, not used for offensive activity

## Future use

Topology data should later feed:

- Asset Inventory
- Network Connection Monitor
- ExposureScout
- Firewall Rule Auditor
- Risk Register Export
- Case Management
