# Kubernetes backup

Kubernetes workloads are described by API objects (Deployments, Services, ConfigMaps, Secrets...) and keep their
data on PersistentVolumes. Fenrir-Backup backs up both into the same repositories as disk images, encrypted and
deduplicated the same way, and restores them on the same cluster or another.

The API objects of chosen namespaces, and the data of their PersistentVolumeClaims through CSI volume
snapshots (below).

## Access

The `k8s` crate talks to the API server over HTTPS with a bearer token, checking the server against the cluster's CA:
in a pod, its service account (`/var/run/secrets/kubernetes.io/serviceaccount`); outside, `--api-server`,
`--token-file` and `--ca-file`. Backing up needs `get` and `list` on the namespaces' objects; restoring needs
`create` (and `update` with `--replace`).

## What is backed up

Discovery lists every namespaced resource type that can be listed and created (core and every API group, including
custom resources; a group whose API service is down is skipped with a warning). Of each type, every object of the
chosen namespaces, except what Kubernetes recreates or keeps for itself:

* objects owned by another (a Deployment's ReplicaSets and their Pods, a CronJob's Jobs): their owner recreates them;
* events, endpoints, endpoint slices, leases, controller revisions;
* `kube-root-ca.crt`, the `default` service account, service-account token secrets.

Each object is cleaned so it can be created again: no uid, resourceVersion, generation, timestamps, managed fields,
owner references or status; a Service loses its allocated cluster IP and node ports (a headless one stays headless);
a claim loses the volume it was bound to; a Job loses its generated selector.

The objects (with their resource type and the namespaces' labels) are one JSON document, stored as a disk of an
image (a 512-byte header with a magic and length, the JSON, zero padding) whose machine is the cluster
(`k8s:<cluster>`) and OS family `kubernetes`. Retention, verification, off-site copies and immutability work as for
any image.

## Restore

`fenrir-backup k8s restore --image ID [--namespace N [--to-namespace M]] [--replace]`: the namespaces are created
(with their labels), then the objects in dependency order (service accounts, secrets and config maps, quotas and
network policies, claims, roles and bindings, services, other kinds, workloads, then autoscalers, disruption budgets
and ingresses). An object that exists is left alone unless `--replace`. Restored under another name, RoleBinding
subjects naming the namespace's service accounts follow it.

## Commands

* `fenrir-backup k8s backup --namespace shop [--namespace ...] [--cluster NAME] [--api-server ... --token-file ... --ca-file ...]`
* `fenrir-backup k8s show IMAGE`: the objects in a backup.
* `fenrir-backup k8s restore --image IMAGE ...`

Run in the cluster, the CLI is a CronJob with a service account and the repository on a mounted volume or S3.

## Volume data

With `--volume-image IMAGE` (the CLI as a container image, `Dockerfile.cli`), each claim of the backed-up
namespaces is backed up too, as another disk of the same image:

1. If its CSI driver has a VolumeSnapshotClass (the default one first): a VolumeSnapshot, then a temporary claim
   created from it (`dataSource`), so the data is one point in time and the running workload is not touched.
   Otherwise the claim itself is read while in use, on the node of the pod using it, and the image is marked
   inconsistent with a warning.
2. A reader pod (`fenrir-backup k8s volume-server --mode read`, as root, the claim mounted read-only at `/data`)
   serves the files as a tar stream (ustar with PAX long names; files, folders and symbolic links). The CLI fetches
   it through the API server's pod proxy, so it works from inside the cluster or outside without opening a port.
3. The reader pod, temporary claim and snapshot are deleted (also after an error).

On restore with `--volume-image`, the claims are created first; then, for each, a writer pod mounts it and receives
the stream (extraction never writes outside the volume, follows no link out of it, and creates no device files); only
then are the workloads created, so they start with their data.

## From the server ("Apps & clusters")

The page connects a tenant or a cluster and picks the machine that runs its backups (any agent: the work is HTTPS
calls, and it reports the `saas` and `kubernetes` capabilities). The secret (client secret, service account key or
token) is sealed **in the browser** to that machine's public key, exactly like a repository passphrase, and stored in
a backup plan (`backup_saas` / `backup_kubernetes` job); the server keeps and forwards only the sealed form, and the
agent opens it for each job and never writes it down. Restores (`restore_saas` / `restore_kubernetes`) run on the same
machine with the plan's sealed secret. Restores that overwrite what is there now (Kubernetes objects replaced,
Salesforce records updated) need the cluster's or tenant's name typed; the server refuses them otherwise.
The backup and restore code is shared by the command line and the agent (`saas::run`, `k8s::repo`).

## Tests

* Unit tests: discovery filtering, what is skipped, cleaning, restore order, the archive format.
* `ci/e2e-kubernetes.sh` (CI job `kubernetes`, a kind cluster): a namespace with a Deployment, Service, ConfigMap,
  Secret, ServiceAccount, Role, RoleBinding, claim and CronJob is backed up, deleted and restored (data equal, the
  Deployment available again, generated objects never in the backup), restored again as another namespace, and a
  third restore over existing objects changes nothing. With the CSI hostpath driver and the snapshot controller
  installed, a claim on it is backed up through a snapshot and one on local-path is read live; after the namespace
  is deleted and restored, every file in both is back byte for byte, links included, and no snapshot, temporary
  claim or pod is left.
