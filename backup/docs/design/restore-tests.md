# Design note: scheduled restore tests

Status: implemented. The KVM path is run against a real CirrOS image in CI,
twice:

* `vmboot` test `cirros_boots_from_a_full_restore`: the full restore, the
  read-back, the boot from the restored disk and the deletion.
* CI job `restore-test` (`ci/e2e-restore-test.py`): the same end to end
  through a real server and agent. The repository is set to a weekly full
  restore test on today's weekday through the API, and the server's own
  scheduler queues the test. The result, the restore facts and the screenshot
  are read back through the API, and the agent's restore folder must be
  gone. The screenshot is kept as a run artifact.

The Hyper-V path has not been run on a Hyper-V host in CI.

A boot check (`vmboot`, `boot.rs`) proves a backup starts. On a KVM host it
streams the disks from the repository and never restores them in full. A
**restore test** goes further. It restores the image completely, boots a VM
from the restored disks, takes a screenshot, and then deletes the VM and its
disks. Each test leaves a record of what was restored, what was read back,
how the boot went, and whether the deletion worked.

## 1. Agent (`BootCheck { full_restore: true }`)

* **KVM hosts:**
  * Every disk is restored as a raw file in
    `<state dir>/restore-tests/<image>`. Each file is read back and matched
    to the backup chunk by chunk.
  * QEMU boots from the files through a throw-away overlay, so the restored
    disks stay exactly as restored (`BootOptions::disk_files`).
  * After the verdict the VM is stopped and the folder deleted. An
    interrupted test's leftovers are cleared before the next one.
* **Hyper-V hosts:**
  * The image is restored as VHDX, booted with its network disconnected,
    and checked by heartbeat.
  * The VM and its folder are then removed. VHDX cannot be read back, but
    the data was still authenticated as it was read from the backup.
* **Result:** `BootCheckResult.restore_test` holds the format, bytes
  restored, restore time, chunks checked, mismatches, and the deletion
  (`vm_removed`, `removed_unix`, `removal_error`).
* **Outcome rules:**
  * A mismatch fails the test, whatever the boot showed.
  * A failed deletion is stated in the message so someone removes the
    VM by hand.
  * `keep_running` is refused with `full_restore`.

## 2. Scheduling

These are repository settings, both in the standalone server and in Fenrir
Cloud:

* **Boot host and interval:** unchanged from boot verification.
* **Full restore test:** every scheduled check is a restore test.
* **Weekday:** an optional UTC weekday (0 = Monday). Scheduled checks are
  only queued on that day.

"Weekly, on Sundays, full restore test" gives one restore test per backed-up
machine each week. Each run tests the newest image of each machine, one at a
time per repository.

## 3. Fenrir Cloud: the ISMS record

* **Every backup job status:**
  * When a backup job finishes (succeeded, warning, failed, cancelled), its
    status goes into the hash-chained audit log as `backup.job.<state>`.
    The entry names the machine, plan, job and error. An overdue plan is
    logged as `backup.job.missed` once per episode.
  * Once a week the past seven days of backup job statuses are filed as
    automated ISMS evidence for backup (control FC-BACKUP: ISO 27001
    A.8.13 and the matching requirements of every adopted framework). The
    evidence holds the full list and its SHA-256.
* **Every restore test** is filed as ISMS evidence for DR testing (control
  FC-DRTEST: ISO 27001 A.5.30 and A.8.13, NIST CSF RC.RP).
  * The evidence holds the machine, the recovery point, the outcome, the
    restore facts, the boot verdict and the VM deletion.
  * The screenshot is stored, encrypted, as the evidence file.
  * The record is also kept in the audit log (`backup.restore_test`).
  * Tests are listed in the ISMS as the DR test log, with the screenshot,
    and can be downloaded as JSON.

## 4. Tests

* **`vmboot`:** CirrOS restored in full to a raw file, read back with no
  mismatch, booted from the file (verified, screenshot), the file unchanged
  and then deleted. A wrong number of files is refused.
* **Agent:**
  * Restore facts and the deletion are recorded.
  * A mismatch fails the test.
  * A failed deletion is reported and kept in the result.
* **Server:**
  * The weekday and full-restore settings are validated and listed.
  * Nothing is queued on another weekday.
  * The scheduled job is a full restore test.
  * The restore facts are kept with the boot check.
  * A manual restore test cannot keep its VM.
* **`cloud/tests/test_restore_tests.py`:**
  * The schedule respects the weekday.
  * A finished test becomes ISMS evidence with the screenshot, linked to
    A.5.30 and A.8.13, and is written to the audit log.
  * Backup statuses are audited, and the weekly backup log is filed once.
