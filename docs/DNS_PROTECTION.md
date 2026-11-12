# DNS protection

Every device gets its own encrypted DNS resolver on the Fenrir server. Windows and Linux agents can also run a
local DNS proxy that sends all lookups there ([EDR_EXCLUSIONS_AND_DNS_PROXY.md](EDR_EXCLUSIONS_AND_DNS_PROXY.md)).
Macs never use the local proxy: a Mac whose DNS points at loopback has no internet whenever the proxy is not
answering, so the macOS agent ignores the setting and puts back any DNS change an earlier version made. Phones and agentless Macs use a profile. The console page **DNS protection** is laid out like Microsoft Defender:

| Investigate | Policies & rules | Threat intelligence |
|---|---|---|
| Overview, Query explorer, Devices | Rules, Allow / block lists, DNS policies | Fenrir ruleset, External feeds |

## How a lookup is decided

First match wins. Each step is recorded, and **Check a domain** (or clicking any logged lookup) shows the full trail.

1. **Rules and allow/block entries**, closest scope first: device, then group (including subgroups), then customer,
   then MSP-wide. Within a scope: priority (lower first), then allow before block.
2. **Policy allow and block lists** (the policy's DNS section).
3. **Threat intel**: an analyst's allow indicator allows; malicious indicators block.
4. **Fenrir ruleset** (below), if the policy uses it.
5. **External lists**: malware lists always block; other lists block where the policy blocks their category. Skipped
   when the policy sets *External blocklists* to *ruleset*.
6. **Categories** blocked by the policy, then the **DGA heuristic**.
7. Otherwise the lookup is resolved normally (with SafeSearch rewrites if enforced).

A policy in *observe* mode logs what would have been blocked and blocks nothing.

## Rules and allow/block lists

**Allow / block lists** are single lines: a domain (which covers its subdomains), an exact name or a wildcard, for
the whole customer or for specific devices or groups. Each can have an expiry date and a note, and each counts hits.
**Import many** takes a pasted list (hosts-file lines and `#` comments are fine). Clicking a lookup in the Query
explorer or on a device offers **Allow / Block on this device** and **Allow / Block for the customer**. Each click
creates an entry, with an optional expiry date.

**Rules** add conditions:

| | |
|---|---|
| Match | domain and subdomains, exact name, wildcard (`*.ads.*.example`), pattern (safe regular expressions only), or category |
| Applies to | the whole customer, device groups (and subgroups), or devices |
| Query types | for example TXT only (DNS tunnelling) or A/AAAA only; none = all |
| Schedule | days and times in the customer's time zone, for example Mon to Fri 08:30 to 15:30 |
| Action | allow, block, or **monitor** (log only) |
| Audit only | records what the rule would do on each matching lookup, and changes nothing |
| Priority, expiry, note | |

Rules and entries on **your MSP tenant apply to every customer**. Customer staff see them, but cannot change them.

**History.** Every change creates a new version, with who made it, when, what changed field by field, and an optional
comment. **Restore** puts back any earlier version as a new version, and deleted rules can be restored the same way.

## Per-device results

**Devices** lists every device with its lookups and blocks today and over 7 days, its last block, and the state of
its local DNS proxy, as reported by the agent:

- *on*: the proxy and its Windows rule are in place;
- *problem*: for example, Group Policy controls name resolution, or port 53 is in use;
- *skipped*: domain controllers and DNS servers;
- *off*.

A device with no lookups in 7 days is flagged **not resolving**: its DNS is not reaching Fenrir.

Opening a device shows:

- the DNS policy in force and which policy layers set it;
- the proxy status and the agent's DNS events;
- 14 days of lookups and blocks, and its most-blocked domains;
- the rules and lists that apply to it;
- its recent logged lookups (each with its full explanation);
- a **Check a domain** that uses that device's own policy, groups and rules.

Lookups and blocks are counted for every query. The **query log** keeps what each policy's *Query logging* setting
asks for: blocked lookups by default, plus anything an audit or monitor rule or the ruleset's monitor band matched.
Set logging to *all* on a policy to see every lookup in the explorer. The explorer filters by device, domain, action,
category, what decided it and time, and exports CSV (cells are escaped so a hostile domain can't become a spreadsheet
formula).

## The Fenrir DNS ruleset

Fenrir builds its own ruleset from the feeds and its threat intel:

- **Weights.** Each source has a weight, set under **Fenrir ruleset → Sources and weights**. Defaults:

  | Source | Weight |
  |---|---|
  | HaGeZi TIF mini | 50 |
  | HaGeZi TIF full | 35 |
  | HaGeZi Pro | 30 |
  | OISD | 30 |
  | Custom lists | 30 |
  | Fenrir threat intel (global malicious domains) | 60 |

- **Score.** A domain's score is the sum of the weights of the sources that list it or a parent domain, capped at 100.
  Agreement counts: a domain on one list scores less than a domain three lists agree on.
- **Block threshold** (default 60). At or above it, the ruleset blocks: malware, phishing, C2, cryptomining and DGA
  categories always, and other categories where the policy blocks them.
- **Monitor threshold** (default 50). Between the two thresholds a domain is kept and logged as *monitor*, never
  blocked. Below it, the domain is left out.
- **Protected domains** are never included: Microsoft, Apple, Google, the big CDNs and certificate authorities, this
  server, and your own additions.
- **Disabled feeds** count towards agreement once you give them a weight. This lets an ads list support a decision
  without blocking anything on its own.

Builds run after the feeds refresh (at most daily, when a feed changed), or on **Build now**. Each build records:

- how many domains it holds, blocking and monitor-only;
- counts by category;
- the sources and weights used;
- the difference from the previous build (domains added and removed, with samples).

The last ten builds are kept, and **Make active** rolls back to any of them. **Test a domain** shows which sources
list a domain, its score now and its score in the active build.

Policies decide how it is used:

- **Fenrir DNS ruleset**: *block* (default), *monitor* or *off*.
- **External blocklists**:
  - *direct* (default): each list also blocks on its own;
  - *ruleset*: lists only count through the ruleset's score, so a domain on a single list stops being blocked by
    that alone.

Settings and builds need the platform permission. Policies are per customer.

## Permissions

| Action | Needs |
|---|---|
| View | read |
| Customer rules and entries | configure |
| MSP-wide rules, the ruleset and external lists | platform |

Every rule change, import, quick entry, ruleset build, activation and settings change is in the audit log.
