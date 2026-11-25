# Google Workspace posture (VULN-12)

**Vulnerabilities → Google Workspace** assesses a customer's Google Workspace and offers a few safe fixes. The code is
in `cloud/fenrir_cloud/google_workspace.py`.

## Connecting

The customer creates a Google Cloud service account. Their super admin authorises its client ID for domain-wide
delegation (Admin console > Security > API controls). Fenrir acts as the admin the customer names.

The scopes are explicit:

| Use | Scopes |
|---|---|
| Read (default) | `admin.directory.user.readonly`, `admin.directory.domain.readonly`, `admin.directory.user.security` |
| Safe changes (only when *Allow safe changes* is chosen) | adds `admin.directory.user` |

Connecting requires step-up authentication. The key is stored encrypted and never returned. The scopes requested
match exactly what the connection records.

## Checks

* Administrators enrolled in 2-Step Verification. A failure lists the accounts.
* Everyone enrolled in 2-Step Verification.
* 2-Step Verification enforced.
* Super administrators: a warning for one, or for more than four.
* Active accounts with no sign-in for 90 days.
* Third-party apps holding OAuth access to administrators' data.
* SPF, DMARC and DKIM (`google._domainkey`) for each verified domain.

A check Google will not answer is marked *unavailable*, with the reason. The 2-Step Verification enforcement setting
itself has no API, so the fix for it is a step in the Admin console.

## Safe changes

There are three, and only when the connection allows changes:
* sign a user out;
* require a new password at the next sign-in;
* suspend a stale account.

Each one requires step-up authentication and typing the account's address. Fenrir reads the user back to verify the
change; a sign-out leaves no state to read back, and the result says so. Every change and every refusal is audited.

Fenrir never changes a super administrator, never turns off 2-Step Verification, and never deletes an account.
