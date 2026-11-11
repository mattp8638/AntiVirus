# Threat intelligence

**Threat intel** in the console looks up hashes, domains, URLs and IPs, checks files, and manages the indicators and
YARA rules that agents and DNS protection use. The server fills it from free public feeds it downloads itself:
nothing goes through a Fenrir-hosted service, and nothing needs a paid subscription.

## The feeds

| Feed | What it adds | How it is used |
|---|---|---|
| MalwareBazaar (abuse.ch) | SHA-256 hashes of malware shared in the last 48 hours | Agents block and quarantine matching files |
| URLhaus links (abuse.ch) | Malware download links still online | Agents block those exact links |
| URLhaus domains (abuse.ch) | Domains used only to spread malware | Blocked by agents and DNS protection |
| ThreatFox (abuse.ch) | C2 domains and IPs, payload links and hashes | As above, by type |
| Feodo Tracker (abuse.ch) | Botnet command-and-control IPs | Firewall-blocked by agents |
| IPsum level 3 | IPs listed by at least three public blocklists | Marked suspicious: shown in lookups and sightings, not blocked |

The abuse.ch data is published under CC0; IPsum is public domain. Each feed refreshes on its own schedule (hourly for
most) in the background. **Threat intel → Feeds** shows when each last updated, how many indicators it holds and any
error. Platform admins can turn a feed off there: its indicators stop being used at once. **Sync feeds now** refreshes
everything immediately.

## Safety rules

- A failed download, an empty result or a file over 120 MB keeps the previous copy.
- A feed that shrinks by more than 80% in one refresh is held back, so a truncated download cannot unblock most of it.
- Indicators expire a few refreshes ahead: if a feed stops updating, its entries age out instead of blocking forever.
- Links from feeds are blocked as exact links, never as whole sites, and shared platforms (GitHub, Google Drive,
  OneDrive, Discord, Dropbox and so on) are never blocked wholesale, whatever the source.
- Your own indicators win: a customer "allow" entry overrides a feed.

## abuse.ch Auth-Key

abuse.ch may require a free Auth-Key for downloads. If the Feeds tab says so, create one at
[auth.abuse.ch](https://auth.abuse.ch), add it to the server's `deploy/.env`:

```
FENRIR_ABUSECH_AUTH_KEY=your-key
```

and restart with `docker compose up -d` (from `deploy/`). The key is only ever sent to abuse.ch.

## YARA rules

Feeds do not add YARA rules automatically. Agents treat each rule's text strings as patterns, so a large community
rule set would raise false alarms on ordinary files. Add the rules you trust under **Threat intel → YARA rules**.
