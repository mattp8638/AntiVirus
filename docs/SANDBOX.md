# Sandbox analysis (AV-15)

**Protection → Sandbox analysis** sends suspicious files to a sandbox the MSP licenses. The code is in
`cloud/fenrir_cloud/sandbox.py` and, on the agent, `agent/linux/pkg/fleet/sample.go`.

## Provider

Fenrir does not include a sandbox. It talks to a CAPE-compatible REST API (`/apiv2`), self-hosted or hosted, with an
API key that is stored encrypted. A provider set on the MSP's own tenant is used for all customers unless a customer
has its own.

**Without a provider, every submission is refused with that reason.** Live verification needs a licensed sandbox:
that dependency is recorded in the parity tracker.

## Customer policy

| Setting | Effect |
|---|---|
| Allow submissions | Off by default. |
| Mode | *Hash lookup only*: the file never leaves the customer. *Upload*: the file is uploaded when the sandbox has not seen its hash. |
| Never-submit paths | Files whose path contains one of these are refused, for example `/HR/` or `Payroll`. |
| Approve executables automatically | Executables and scripts skip manual approval. |

Further controls apply regardless of these settings:
* A file that PII discovery reported as holding personal data is always refused.
* Documents, email and archives always need approval by a person other than the requester.

## Data path

1. A technician submits a file from an alert (its SHA-256, path and quarantine record) or by hash.
2. The policy decides one of: refused, waiting for approval, or approved.
3. Once approved, Fenrir first looks the hash up. If the sandbox analysed it before, that analysis is used.
4. If the hash is unknown and uploading is allowed, the agent runs `sample.collect`:
   * it reads the file from quarantine only;
   * it checks the file against the quarantine record's SHA-256;
   * it uploads the file as the command's artifact, at most 32 MB.

   The cloud checks the uploaded SHA-256 again and submits the file.
5. The scheduler polls the sandbox until the report is ready, for up to six hours.

## Verdict

The score becomes the verdict:

| Score | Verdict |
|---|---|
| 7 or more | malicious |
| 4 to 7 | suspicious |
| below 4 | clean |
| no score | unknown |

Signatures and network indicators (domains, hosts) are kept with the verdict. The verdict is added to the alert and
to the incident timeline. A malicious verdict raises the alert to high severity, or opens an alert when there was
none.

Each step is audited: requested, refused, approved, submitted and verdict.

## Limits

* Windows agents cannot upload samples yet. For them, only the hash is looked up, and the submission says so.
* Only CAPE-compatible providers are supported. Other sandbox APIs would need their own adapter.
