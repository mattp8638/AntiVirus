# Design note: moving between servers (Fenrir-Backup to Fenrir Cloud)

Status: implemented.

Repositories and their keys stay where they are; only the management moves.

1. **Existing repositories.** New repository › "It already exists": the
   location (folder, share, S3, Azure), the machines that use it, and its
   existing passphrase, encrypted in the browser for each machine as
   always. Nothing is created: the first machine opens the repository and
   lists its images, reporting the repository's own ID (agents report it
   with every listing). The repository becomes ready with its whole history.
   The same repository cannot be added twice. The passphrase and the
   recovery key keep working; the repository is unchanged.
2. **Plans.** The standalone server's Settings › "Move to Fenrir Cloud"
   downloads `fenrir-backup-export.json` (`GET /api/export`): repositories
   (name, location, ID, settings) and plans (machine ID, repository ID,
   what, schedule, retention, off-site copy). It holds no secrets:
   passphrases and sign-ins only ever exist sealed to machines. Fenrir
   Cloud imports it: each plan is recreated for the machine with that
   machine ID and the repository with that ID, both already in Fenrir Cloud
   (machines re-enrolled there, repositories added as existing); plans it
   cannot match are listed and skipped.
3. **Machines** enrol in Fenrir Cloud with its installers (the backup agent
   comes with the Fenrir agent); their machine IDs do not change.

Tests: the server adopts an existing repository from the machine's listing
(ID and images), refuses a second registration of it, and exports plans
without secrets; Fenrir Cloud adopts an existing repository and imports the
export (matched plans recreated, the others reported).
