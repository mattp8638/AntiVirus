# Strict EDR exclusions and the local DNS proxy

## Strict EDR exclusions

Name-only exclusions (`exclusionProcesses`, "powershell.exe") let any file with that name through. Use **EDR exclusions** (console: Security → EDR exclusions; API: `/api/console/edr/exclusions`) for RMM agents and other tooling instead. Every rule is bound to file content:

| Kind | Trusts | Required |
|---|---|---|
| `process-chain` | A child process whose **parent's full path and SHA-256** both match. Optional child path, child SHA-256 and command-line filters narrow it. | Parent path (wildcards only in the file name) and at least one parent SHA-256 |
| `hash` | One exact file, optionally also bound to its path | At least one SHA-256 |

Each rule lists what it relaxes:

- `behavior`: attack-surface and application-control rules on the agent (Windows `ProcessGuard`, Linux/macOS `SenseOnce`).
- `antimalware`: signature and ML verdicts on the child image. This scope needs the child's SHA-256.
- `sigma`: cloud detection alerts. The rule match is still stored for hunting.

**Add RMM agent** creates one `process-chain` rule per script interpreter (PowerShell, pwsh, cmd, cscript and wscript on Windows; bash, sh, python3 and pwsh on Linux; plus zsh on macOS), all pinned to the agent's hash. Add the hash of every agent version you run. An agent update with a new hash is not trusted until you add it. That is intended.

A rule always fails closed. A missing or different hash, a copy in another folder or a wildcard directory never matches. Customer admins can only add rules for their own customer. Platform-wide rules need the `platform` permission. Expired and disabled rules stop applying immediately, and every create, update and delete is audited.

Agents report each use as `edr.exclusion.applied` and the console shows the hit count per rule. Agents hash a parent only when a rule names its path, and they cache hashes by path, size and modification time. When they hash a parent, they add `parentSha256` to the process event so the cloud can verify the chain for `sigma` rules.

## Local loopback DNS proxy (Linux and macOS agents)

Policy `dns.localProxy` (off by default) makes the agent answer DNS on `127.77.0.53:53`:

1. Each query goes to the device's private DoH URL. The cloud applies policy, intel and blocklists and returns its decision in `X-Fenrir-Dns-Action` and `X-Fenrir-Dns-Reason`.
2. The decision is cached locally for `dns.localCacheMinutes`. A domain the cloud blocked stays blocked while the device is offline.
3. With `dns.sinkholeInterception` (on by default) blocked names resolve to the loopback sinkhole `127.77.0.1`. It records the program that tried to connect: the HTTP `Host`, or the TLS server name read from the ClientHello. HTTP gets a block page. TLS connections are closed without a certificate, so nothing is decrypted. Each attempt is reported as `network.sinkhole.connection` with the process path, PID and command line.
4. If the cloud is unreachable, uncached names use the previous system resolvers (`localProxyFailMode: open`) or are refused (`closed`).

The proxy dials the cloud with addresses pinned at start, so it never resolves its own upstream through itself. The system resolver is changed only after the proxy answers:

- systemd-resolved: a `resolved.conf.d` drop-in with `DNS=127.77.0.53` and `Domains=~.`
- plain Linux: `/etc/resolv.conf` is backed up and replaced
- macOS: `networksetup` per network service, with `lo0` aliases for the loopback addresses

The change is undone when the setting is turned off or the agent stops. A marker in the state directory lets the next start undo a change left by a crash.

**Limits.** On systemd-resolved, per-link DNS from DHCP or VPNs may still answer some split-DNS names. The macOS path is compiled and unit-tested but has not yet been checked on a real Mac. The Windows service does not run the proxy. Windows devices keep the cloud DoH URL and destination protection.
