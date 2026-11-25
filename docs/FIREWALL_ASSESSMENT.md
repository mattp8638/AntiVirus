# Firewall configuration assessment (VULN-13)

**Vulnerabilities → Firewall configuration** assesses a firewall's saved configuration. The code is in
`cloud/fenrir_cloud/firewall_config.py`.

## Credentials

Fenrir never asks for the firewall's password. A technician exports the configuration from the firewall's own backup
page and uploads it. The file is read in memory, and only these are kept:
* the findings;
* the file's SHA-256, so the evidence can be matched to the exact file;
* the firmware version.

The file itself is not stored, because it holds password hashes, keys and certificates. A file that declares a
DOCTYPE or XML entities is refused.

## Supported firewalls

| Vendor | Export | Checks |
|---|---|---|
| pfSense (CE and Plus) | `config.xml` from Diagnostics > Backup & Restore | all below |
| OPNsense | `config.xml` from System > Configuration > Backups | all below |

Other vendors are refused with a message rather than given a clean result: FortiGate, SonicWall, Sophos, WatchGuard,
Cisco, MikroTik and UniFi. Their exports are proprietary or need vendor APIs.

## Checks

* WAN rules that pass any traffic from anywhere (critical).
* Management reachable from the internet: WAN rules to the firewall itself or to ports 22, 80, 443, 8080, 8443 or
  10443.
* Web GUI over HTTP, or with the referer check turned off.
* SSH accepting passwords, or allowing root sign-in.
* SNMP with a default or empty community.
* No remote syslog server.
* UPnP / NAT-PMP turned on.
* IPsec using any of:
  * DES, 3DES, Blowfish or CAST;
  * MD5 or SHA-1;
  * DH groups 1, 2, 5, 22, 23 or 24;
  * a pre-shared key shorter than 20 characters.
* OpenVPN using Blowfish, DES or no cipher; OpenVPN without a TLS auth key.
* Disabled rules left in the rule set (information only).
* Firmware older than the oldest supported release. The configuration file does not record the running release, so
  the technician enters both versions.

Each finding names the setting it came from.

## Not checked

These are always listed as not checked:
* password strength (only hashes are in the file);
* the live running state;
* installed package versions.

Firmware is listed as not checked when the versions were not given.
