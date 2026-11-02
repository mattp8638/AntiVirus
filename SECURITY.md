# Security policy

Fenrir controls every device it manages, so a vulnerability in it can matter a lot. Please report one privately.

## Reporting a vulnerability

Use **Report a vulnerability** on this repository's **Security** tab (GitHub private vulnerability reporting). Do not
open a public issue, discussion or pull request for it.

Include what you can:

- the component (cloud server, console, Windows agent, Linux/macOS agent, Android app, installers);
- the version or commit;
- how to reproduce it, and what an attacker gains.

Fenrir is free and maintained on a best-effort basis: there is no promised response time or fix date, and no bug bounty.

## Supported versions

Only the latest commit on `main` receives fixes. Keep your server and agents updated.

## Running Fenrir safely

The README's "Use at your own risk" section and `docs/GO_LIVE.md` cover the essentials: HTTPS, MFA for every console
account, a restricted console network list, protected signing and vault keys, off-site backups, and testing changes on a
small group of devices first.
