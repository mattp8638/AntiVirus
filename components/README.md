# Vendored components

Curated source copies of the repositories merged into Fenrir. Each is a snapshot of the branch `claude/jolly-goodall-5kpl2t` at the commit below.

| Folder | Source | Commit |
|---|---|---|
| `sentinel/` | github.com/Palmertech-Webdev/Sentinel | `756b7aba7f9c0ac8c01edeb2812fb135cdbdd03d` |
| `siem/` | github.com/Palmertech-Webdev/SIEM-Work-Dev | `fae91209ce40a08451f6d9e9e2bcb79f4af0e497` |
| `crm/` | github.com/zy538324/Palmertech-CRM | `4537ab426c20f28aba4ac5a04dac78f28c03b690` |
| `signaturedb/` | github.com/zy538324/signaturedb-fenrir | `2b6950f1d1940d5683401e2fc9561ee872fcaee8` |

## How they are used

- **sentinel:** its incident playbooks (`playbooks/templates`) are copied into `cloud/fenrir_cloud/playbooks` and drive incident checklists. The whole Sentinel API can be mounted at `/legacy/sentinel` with `FENRIR_ENABLE_LEGACY=1`.
- **signaturedb:** deploy unchanged to Cloudflare (`wrangler deploy`). Fenrir Cloud pulls its `/api/v1/agent/bundle` hourly when `FENRIR_FEED_SYNC=true`.
- **siem:** reference for features still being migrated (RMM, patch evidence, compliance evidence). See `docs/ROADMAP.md`.
- **crm:** reference for the console's CRM screens, which were rebuilt on the Fenrir API.

## Deliberately not copied

- **Build outputs and binaries:** `node_modules`, `package_tmp`, `__pycache__`, installers (`.exe`, `.zip`), `dist`.
- **Runtime data captured from a real machine:** Sentinel `agent/evidence/*`, `agent_state.json`, `data/*.json`, scan and case reports, `sentinel.db`. These contained hostnames and host details.
- **A 17 MB NVD snapshot.** Fenrir uses OSV.dev and CISA KEV live instead.
- **Offensive tooling from the SIEM penetration module:** virus and worm generators, backdoor creation, payload/exploit delivery, brute-force tools and log/artifact wiping (`gaining_access/`, `maintaining_access/`, `covering_tracks/`, `main_recon.py`). These do not belong in a defensive product. Asset discovery, port and vulnerability scanning, and DNS/email posture checks were kept.
