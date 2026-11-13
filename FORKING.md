# Making Fenrir yours

Fenrir is Apache 2.0 software, published as a **starting point**. There is no upstream to install from and nobody
maintains it for you: you fork it, run it from your own copy, and you look after your copy. This page is the checklist
for doing that well, written for a small MSP setting it up for the first time.

## 1. Make your own copy

1. On GitHub, click **Use this template** (a clean copy with no history) or **Fork**. Make the copy **private** if you
   plan to change it for your business.
2. Turn on, under your copy's **Settings → Code security**:
   - Dependabot alerts and security updates;
   - secret scanning with push protection;
   - private vulnerability reporting.
3. Protect `main` under **Settings → Branches**: require pull requests and passing checks before merging, even if
   you are the only one working on it.
4. Use a passkey or hardware key for your GitHub account. Your servers install whatever your repository releases, so
   your account is the key to every machine you manage.

## 2. Install from your copy

```bash
git clone https://github.com/<your-org>/<your-fork> /opt/fenrir && cd /opt/fenrir
sudo deploy/install.sh --domain rmm.example.com --email you@example.com --company "Your Company"
```

- **Updates follow your copy.** `deploy/auto-update.sh` pulls from the repository the server was cloned from. Tag a
  release on your `main` (`git tag vX.Y.Z && git push origin vX.Y.Z`), `release.yml` tests it, and your servers on the
  stable track install it overnight. Nothing else can push changes to them.
- **Everything else is self-contained.** Each server makes its own:
  - code-signing certificate and release key;
  - HTTPS certificate;
  - STUN for direct remote sessions;
  - agent downloads;
  - encrypted backups.
- `install.sh` shows the repository the server will update from. If it is not yours, stop and clone your copy instead.

## 3. Put your name on it

| What | Where |
|---|---|
| Your company name, logo and colours in the console, agent window and reports | **Settings → Branding**, per server; no code change needed |
| Product name, if you rebrand the software itself | `console/src/brand.tsx`, the Windows installer resources (`agent/windows/installer`) |
| Android app ID | `agent/android/app/build.gradle.kts` (`applicationId`, `namespace`) and the Kotlin package folders. Set it before your first phone enrolment: phones cannot upgrade between apps with different IDs. |
| Apple web-protection profile ID | `cloud/fenrir_cloud/web_profile.py` (`PROFILE_ID`) |
| Windows MSI upgrade code | `cloud/fenrir_cloud/rmm_deploy.py` (`UPGRADE_CODE`), so your MSI never upgrades someone else's |
| Code-signing publisher shown by Windows | `FENRIR_CODESIGN_NAME` and `FENRIR_CODESIGN_URL` in `deploy/.env` |
| Security contact | `FENRIR_SECURITY_CONTACT` (publishes `/.well-known/security.txt`) and `SECURITY.md` |

`python3 scripts/handoff/public_check.py --private "<old names>"` finds names or addresses you have not replaced yet,
if you start from someone else's fork.

## 4. Before your first customer

Work through [docs/GO_LIVE.md](docs/GO_LIVE.md). The essentials:

- `deploy/preflight.sh` reports no failures.
- Backups are scheduled, encrypted (`FENRIR_BACKUP_PASSPHRASE`) and copied off the server. A restore has been tested.
- MFA is on for every console account.
- `.env`, the signing keys and the backup passphrase are copied to an offline password manager.
- Agents are tested on a few of your own machines before customers'.

## Keep these promises to your users

- Never commit signing keys, `.env` files, customer data or exports. The repository `.gitignore` and
  `deploy/preflight.sh` help with that.
- Keep the community catalogue's checksums (`catalogue/manifest.py --write` after reviewing a change): servers only load
  catalogue files that match.
- Say clearly whether you offer support for your copy. The original offers none.
