# Fenrir feed service replacement

This replacement turns `api.fenrir-security.co.uk` into a focused Cloudflare-hosted update service for endpoint agents.

## What it does

- Pulls hash intelligence from MalwareBazaar
- Pulls URL intelligence from URLhaus
- Pulls YARA rules from YARAify
- Pulls raw Suricata and ClamAV-compatible rule text from configurable upstream URLs
- Stores the latest normalised bundle in D1-backed state when running on Cloudflare
- Exposes agent-friendly endpoints with ETag support for light polling
- Supports scheduled sync on Cloudflare every 30 minutes
- Supports on-demand admin-triggered sync

## Endpoints

- `GET /health`
- `GET /api/v1/feeds/manifest`
- `POST /api/v1/admin/feeds/sync`
- `GET /api/v1/admin/feeds/summary`
- `GET /api/v1/agent/bundle`
- `GET /api/v1/agent/hashes.ndjson`
- `GET /api/v1/agent/urls.ndjson`
- `GET /api/v1/agent/rules/yara`
- `GET /api/v1/agent/rules/suricata`
- `GET /api/v1/agent/rules/clamav`

## Secrets to set in Cloudflare

- `FENRIR_FEED_ADMIN_TOKEN`
- `FENRIR_ENDPOINT_TOKEN`
- `FENRIR_MALWARE_BAZAAR_AUTH_KEY`
- `FENRIR_YARAIFY_AUTH_KEY`

Optional:
- `FENRIR_URLHAUS_AUTH_KEY`
- `FENRIR_SURICATA_URL`
- `FENRIR_CLAMAV_URL`
- `FENRIR_ALLOWED_CORS_ORIGINS`
- `FENRIR_ALLOW_ALL_CORS_ORIGINS`

## Example agent flow

1. Agent requests `GET /api/v1/feeds/manifest`
2. Agent compares the returned ETag or version to its local definitions version
3. If changed, agent downloads `/api/v1/agent/bundle` or the specific NDJSON / rule endpoints
4. Agent applies the new signatures locally and stores the returned version

## Notes

- The current implementation stores the latest feed bundle as one persisted state object, which is practical for a feed delivery MVP on Cloudflare but not ideal for very large long-retention intelligence datasets.
- If you want full-scale production retention, the next step is moving hashes, URLs, and rules into first-class D1 tables with incremental sync cursors per source.
