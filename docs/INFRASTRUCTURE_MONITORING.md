# Infrastructure monitoring (RMM-14)

**Network → Infrastructure** monitors Proxmox VE and VMware vCenter through their own APIs. Fenrir reads the state
each provider reports, which tells it more than whether a port answers. The code is in `cloud/fenrir_cloud/infra.py`
and, on the agent, `agent/linux/pkg/fleet/infrapoll.go`.

## What is read

| Provider | Hosts | Virtual machines | Storage | Credential |
|---|---|---|---|---|
| Proxmox VE | nodes (online/offline, CPU, memory) | VMs and containers (state, node) | storage (active, used/total) | API token `user@realm!name` with a read-only role |
| VMware vCenter | hosts (connection and power state) | VMs (power state, host) | datastores (capacity, free) | a user with a read-only role (vSphere Automation REST API) |

Each virtual machine and storage item records the host it belongs to.

## Alerts

Alerts take dependencies into account:
* **Source unreachable or credential refused:** one alert. All its assets become *unknown* and raise nothing of their
  own.
* **Host offline or not responding:** one critical alert. The virtual machines on that host are *suppressed* with the
  reason.
* **Virtual machine not in its expected state:** a high-severity alert. The expected state is taken from the first
  read (running VMs are watched). It can be set to *running*, *stopped* or *not watched*.
* **Storage at 90% used or more, or inactive:** an alert.

Alerts are deduplicated per asset and resolved when the asset recovers.

## How Fenrir reaches the API

* **Directly**, from the Fenrir server. Public addresses only; a private address is refused by the address guard
  (see `PHASE1_HARDENING.md`).
* **Through a device on that network**, with the `infra.poll` command:
  * The command names only the source.
  * The agent fetches the address and credential once, for that command
    (`POST /api/v1/devices/<id>/commands/<command>/infra-credential`). The credential is never in the payload or on
    disk, and each release is audited.
  * The agent sends only the provider's fixed read requests: GETs, plus vCenter's session sign-in and sign-out. It
    refuses non-HTTPS, loopback and link-local addresses.
  * Supported on the Linux and macOS agents. The Windows agent does not support `infra.poll` yet.

Credentials are stored encrypted. Adding a source requires step-up authentication.

## Not covered yet

* Hyper-V and Nutanix;
* cloud workloads (Azure, AWS);
* infrastructure roles such as AD DS, DNS, DHCP and IIS;
* polling from the Windows agent.
