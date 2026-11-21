# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
**"Report a vulnerability"** button on this repository's Security tab
(private vulnerability reporting). Do not open a public issue.

Include what you found, affected versions, and steps or a proof of concept
if you have one. We will:

* acknowledge your report within **5 working days**;
* give an initial assessment within **10 working days**;
* keep you informed, agree a disclosure date with you (normally no later
  than **90 days** after the report), and credit you unless you prefer not.

We will not take legal action against good-faith research that respects
users' data and privacy, avoids service disruption, and gives us reasonable
time to fix the issue before disclosure.

Areas we especially want to hear about: anything that lets an attacker with
access to backup storage read, alter, roll back or delete backups unnoticed;
key handling; parsing of repository data; anything that writes to a disk the
user did not select.

## Support lifecycle

Fenrir-Backup is pre-release (0.x). Until 1.0:

| Version | Security fixes |
|---|---|
| Latest 0.x minor release | Yes |
| Older 0.x releases | No — upgrade to the latest |

From 1.0 onwards, support is per major version. Minor and patch releases
within a major version are compatible upgrades, so fixes ship in the latest
minor release of each supported major version.

| Major version | Security fixes |
|---|---|
| Current | Yes |
| Previous | For 12 months after the next major version is released |
| Older | No (end of life) |

End of support for any release line is announced at least **12 months** ahead,
in the release notes and on the repository's Releases page.
The repository format is versioned (docs/FORMAT.md); every release can read
every earlier format version, so upgrading never strands existing backups.

## Release integrity

Starting with the first tagged release, each release publishes SHA-256
checksums and a CycloneDX SBOM, and Windows binaries are
Authenticode-signed. (No release has been made yet; the release pipeline is
tracked in the code-of-practice document.) See
[docs/SECURITY-CODE-OF-PRACTICE.md](docs/SECURITY-CODE-OF-PRACTICE.md) for
how we build and maintain the software.
