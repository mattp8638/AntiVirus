# Archive tiers

Long-term copies (an off-site copy kept for years, a repository for monthly and yearly backups) do not need the
fastest storage. A repository on S3 or Azure can keep its backup data in a cheaper **storage tier**:

| Storage | Tiers offered | Not offered, and why |
|---|---|---|
| S3 (AWS and compatible) | `STANDARD_IA`, `ONEZONE_IA`, `INTELLIGENT_TIERING`, `GLACIER_IR` (Instant Retrieval) | Glacier Flexible Retrieval and Deep Archive: every object needs a restore request (hours) before it can be read, so verification, restores and maintenance could not run |
| Azure Blob | `Cool`, `Cold` | `Archive`: blobs must be rehydrated (hours) before every read |

Only **chunks** (`chunks/…`, also a dedup group's shared `…/chunks/…`) are written with the tier: they are nearly
all of a repository. The configuration, manifests, key slots and locks stay in the default tier, so listing
backups, unlocking and maintenance stay fast and free of retrieval fees. Every tier offered is read at once, so
restores, verification and boot checks work exactly as in the default tier; reads cost a retrieval fee per GB
and objects have a minimum storage duration (30 to 90 days), which the provider charges if a prune deletes them
earlier, so the tier suits repositories whose backups are kept longer than that.

How it is used: create the repository with a tier (Repositories › New repository › Storage tier; CLI
`FENRIR_S3_STORAGE_CLASS` / `FENRIR_AZURE_TIER`), then point a plan's off-site copy at it, with a retention that
keeps monthly and yearly backups there. The server checks the value; the S3 emulator test in CI writes chunks with
a tier and reads them back, and a tier the service does not know is refused.
