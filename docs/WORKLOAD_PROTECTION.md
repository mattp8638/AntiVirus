# Server and workload protection (AV-21)

**Protection → Workload protection** covers servers and container hosts. The code is in
`cloud/fenrir_cloud/workload.py` and, on the agent, `agent/linux/pkg/fleet/fim.go` and `containers.go`.

## Support and permission matrix

| Module | Windows | Linux | macOS | What the agent needs | Data path |
|---|---|---|---|---|---|
| File integrity monitoring | not yet | yes | yes | read access to the watched files (the agent runs as root) | `fim.scan` command → manifest of hashes and metadata → baseline and comparison in the cloud → alert |
| Container runtime posture | not yet | yes (Docker, Podman) | yes (Docker, Podman) | the `docker` or `podman` command-line tool and access to its daemon or socket | `container.inventory` command → `ps` and `inspect` (read-only) → findings → alert |
| Container image vulnerability scanning | no | no | no | — | open |
| NAS and storage scanning | no | no | no | — | open (mounted shares can be scanned with the normal on-demand scan) |

## File integrity monitoring

Watched paths come from the customer's settings. Without settings, Fenrir watches:
* `/etc/passwd`, `/etc/shadow` and `/etc/group`;
* sudoers;
* SSH server configuration;
* cron;
* PAM;
* systemd units;
* `/etc/hosts` and `/etc/ld.so.preload`;
* root's `authorized_keys`.

**Limits.** At most 200 paths and 5,000 files per scan. Files over 64 MB are hashed on their first 64 MB.

**What is recorded.** For each file: SHA-256, size, permissions, owner and modification time. For a link: its target.

**Baseline.** The first scan becomes the baseline. The baseline is stored in Fenrir, not on the device, so changing it
needs a person in the console.

**Comparisons.** Each later scan is compared with the baseline file by file: added, removed, or changed (which
fields). Any change raises an alert, high severity when it touches account, privilege, SSH, PAM or library-preload
files. **Accept latest scan as baseline** records who accepted it and resolves the alert.

## Container runtime posture

The agent lists running containers with the container tool's own read-only commands, and reports for each:
* image;
* user;
* mounts;
* risky settings:
  * privileged mode;
  * the host's network or PID namespace;
  * running as root;
  * added `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE` or `ALL` capabilities;
  * sensitive host paths mounted (the runtime's socket, `/`, `/etc`, `/root`, `/proc`, `/sys`, `/dev`, `/boot`).

A privileged container, or one that mounts a sensitive host path, raises a high-severity alert. Other risks are
listed without an alert.

## Schedules

Turning on daily scans in the customer's settings sends both commands once a day to each Linux and macOS device.
Scans can also be requested by hand.
