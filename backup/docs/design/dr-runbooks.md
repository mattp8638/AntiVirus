# DR runbooks

A boot test (phase-3) proves one backup starts. Recovering a site means starting several machines, in an order
(directory and databases before the applications that need them), on whatever hosts are left, and knowing how long
it takes. A **runbook** describes that; a **run** carries it out, as a test or for real.

Implemented in Fenrir Cloud (`fenrir_cloud/backup.py`, `routers/backup.py`; console **Backups › DR runbooks**).

## Runbook

* Groups, in order; each holds machines (a backed-up machine or Hyper-V VM, as listed in Images & restore) and, per
  machine, the host that starts it (a Linux host with QEMU or a Hyper-V host of the same customer), and optionally
  memory, CPUs and a folder for the VM (Hyper-V).
* Optionally tested every N days, and how long test VMs are left running before they are stopped.

## Run

1. All machines of the current group are started at once: for each, the newest image in a repository the host can
   read is booted as a VM with a boot check that leaves the VM running (`boot_check`, `keep_running`).
2. A machine is **up** when its boot check is verified (the guest reported in), **warning** when only its screen
   could be checked, **failed** otherwise (no backup, no access, did not start).
3. When every machine of the group is done, the next group starts; a failed machine stops the run and the rest is
   skipped. Each machine's time from the start of the run to being up is recorded; the run's recovery time is the
   longest.
4. A **test** stops its VMs after the runbook's time (or on **Stop**); a failed test raises an alert. A **failover**
   (destructive permission, password check and the runbook's name typed) leaves them running as the production
   systems.

Runs need no repository unlock (like scheduled boot tests): nothing leaves the hosts, and the data never passes
through the server.

## Tests

`cloud/tests/test_device_backup.py` `test_dr_runbook_starts_groups_in_order_and_stops_test_vms`: a host without
access fails the first machine and skips the rest; with access, group 2 starts only after group 1's boot check is
verified; the recovery time is reported; Stop sends `stop_vm` for the VMs still running; a failover needs the name and
a fresh password check.
