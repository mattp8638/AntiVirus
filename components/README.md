# Vendored components

| Folder | What it is |
|---|---|
| `signaturedb/` | The signature and threat-feed service. Deploy it unchanged to Cloudflare (`wrangler deploy`); Fenrir Cloud pulls its `/api/v1/agent/bundle` hourly when `FENRIR_FEED_SYNC=true` and `FENRIR_FEED_URL` points at it. |
