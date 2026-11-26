# Design note: restoring to Azure and AWS, and standby VMs

Status: implemented. The upload paths are tested against the Azure Storage
emulator (Azurite) and an S3 emulator (moto); creating the VMs in Azure or
AWS from them has not been run against the real clouds.

## 1. Azure

Target `Azure { location: azure://container/prefix, endpoint, name, sealed }`
(agents that report `restore_cloud`). For each disk:

* a page blob `<name>-disk<N>.vhd` is created at the disk size rounded up to
  a whole MiB plus 512 bytes (Azure needs whole-MiB VHDs); an existing blob
  is never overwritten;
* the engine restores into it, writing only non-zero pages (at most 4 MiB
  per request, 512-byte aligned), so upload time follows the data, not the
  disk size;
* the fixed-VHD footer (Microsoft VHD specification) goes last.

The job returns the blob URLs and Azure CLI commands that make managed disks
from them (`az disk create --source <blob> --source-storage-account-id ...`,
generation V2 for UEFI systems) and a VM (`az vm create --attach-os-disk`).
The storage account and its key or SAS token are sealed in the browser to the
restoring machine (as repository keys are); the server never sees them.

## 2. AWS

Target `Aws { location: s3://bucket/prefix, endpoint, region, name, staging,
sealed }`. Each disk is written as a dynamic VHDX into a new folder under
`staging` on the restoring machine (it needs room for the data), uploaded as
`<name>-disk<N>.vhdx` with S3 multipart upload (parts of at least 5 MiB, at
most about 9,000 parts; an upload that fails is aborted) and removed. The job
returns the `aws ec2 import-image` command (VHDX disk containers, UEFI boot
mode when the system booted that way), which needs the `vmimport` service
role. The access key and secret are sealed to the restoring machine.

## 3. Windows from physical machines

Windows backed up from a physical machine may need its storage drivers
prepared before it starts on virtual hardware; the job warns (only for an
image that records Windows, not for a plain disk backup), and the
recovery media's hardware fix-up (`phase-5-hardware.md`) is the remedy.

## 4. Standby VMs

A plan can keep a **standby VM**: after each successful backup Fenrir Cloud
queues a restore of the newest image on the standby host, as a Hyper-V VM or
as QEMU, VirtualBox or VMware files (`replace: true`):

* the disks are written to a new folder `<name>-<image time>`;
* a Hyper-V standby is refused while its VM is not off (it may be in use
  after a failover), leaving it untouched; otherwise the previous VM is
  removed and a new one made with the same name on the new disks;
* only then is the previous standby folder removed (recorded in the agent's
  `standby.json`), so a failed refresh leaves the last good standby.

The standby host needs access to the plan's repository; without it the
refresh is skipped and an alert raised (`backup.standby_failed`). A refresh
writes all of the image's data: suited to hourly or daily plans.

## 5. Tests

* `vdisk::vhd`: footer fields, checksum and geometry; QEMU reads a fixed VHD
  at the right size.
* `azstore` with Azurite: a disk restored into a page blob reads back with
  the data, unwritten zero pages and the footer; existing blobs are not
  overwritten; unaligned writes are refused.
* `s3store` with moto: a 12 MiB file uploads in three parts as one object,
  byte for byte.
* Agent: names, Azure and AWS CLI commands.
* `ci/e2e-s3.py`, end to end with a real server and agent: a disk backed up
  to S3 is restored for AWS (a VHDX uploaded to moto; the staging copy is
  removed) and for Azure (a page blob on Azurite, every chunk read back by
  the agent). Both are downloaded independently of Fenrir, by boto3 and a
  Shared Key request written in the test, and their disk content equals the
  source byte for byte (`qemu-img` reads the VHDX; the VHD ends in its
  footer and is whole MiB). The restore evidence is verified, its hashes
  match what was downloaded and it has RPO and RTO. Restoring to the same
  blob again fails and leaves it unchanged. Creating the managed disk, image
  and VM needs a real Azure or AWS account and is not run.
* `cloud/tests/test_device_backup.py`: cloud targets validated and carried
  with the sealed keys; standby settings validated, listed, and the standby
  restore queued for the new image with `replace`.

CI runs the emulator tests when `FENRIR_TEST_AZURE` and `FENRIR_TEST_S3` are
set (commands that start Azurite and moto or MinIO on a given port).
