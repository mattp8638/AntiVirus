"""Catalogue of remote actions agents understand.

The type strings and required fields match ``AgentService::ExecuteCommand`` in
the Windows service. The Linux agent implements the subset marked with
"linux". The console builds its response menu from this list.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandSpec:
    type: str
    label: str
    group: str
    permission: str = "respond"  # respond | configure | platform
    needs: tuple[str, ...] = ()  # targetPath | recordId
    platforms: tuple[str, ...] = ("windows",)
    destructive: bool = False
    description: str = ""


ALL = ("windows", "linux", "macos")

CATALOG: tuple[CommandSpec, ...] = (
    CommandSpec("device.isolate", "Isolate from network", "Containment", platforms=ALL,
                description="Cut all traffic except Fenrir Cloud and the isolation allowlist."),
    CommandSpec("device.release", "Release from isolation", "Containment", platforms=ALL),
    CommandSpec("process.terminate", "Kill process", "Containment", needs=("targetPath",), platforms=ALL, destructive=True),
    CommandSpec("process.tree.terminate", "Kill process tree", "Containment", needs=("targetPath",), platforms=ALL, destructive=True),
    CommandSpec("scan.targeted", "Scan path", "Scanning", needs=("targetPath",), platforms=ALL),
    CommandSpec("scan.quick", "Quick scan", "Scanning", platforms=ALL),
    CommandSpec("scan.full", "Full scan", "Scanning", platforms=ALL),
    CommandSpec("remediate.path", "Remediate file", "Remediation", needs=("targetPath",), platforms=ALL, destructive=True),
    CommandSpec("persistence.cleanup", "Remove persistence", "Remediation", destructive=True),
    CommandSpec("quarantine.restore", "Restore from quarantine", "Remediation", needs=("recordId",), platforms=ALL),
    CommandSpec("quarantine.delete", "Delete quarantined file", "Remediation", needs=("recordId",), platforms=ALL, destructive=True),
    # No agent keeps file snapshots yet, so rollback is not offered on any platform.
    CommandSpec("ransomware.rollback", "Roll back ransomware changes", "Remediation", platforms=(), destructive=True,
                description="Not available yet: agents do not keep rollback snapshots."),
    CommandSpec("threatintel.lookup", "Threat-intel lookup", "Investigation", needs=("targetPath",)),
    CommandSpec("threatintel.pack.ingest", "Push intel pack", "Investigation", permission="configure"),
    CommandSpec("support.bundle", "Collect support bundle", "Investigation", platforms=ALL),
    CommandSpec("support.bundle.sanitized", "Collect sanitised bundle", "Investigation"),
    CommandSpec("forensics.collect", "Collect forensic triage package", "Investigation", platforms=ALL,
                description="Processes, autoruns, network, event logs and prefetch in one archive."),
    CommandSpec("inventory.refresh", "Refresh inventory", "Investigation", platforms=ALL),
    CommandSpec("network.probe", "Probe network services", "Investigation", platforms=ALL,
                description="Sent automatically for network monitors that probe from this device; checks TCP services on its LAN."),
    CommandSpec("script.run", "Run script", "Administration", permission="configure", platforms=ALL,
                description="Run a script from the library. Pick it on the Scripts page to fill in parameters."),
    CommandSpec("device.reboot", "Restart device", "Administration", platforms=ALL, destructive=True,
                description="Restart now, or after the delay in the payload (minutes)."),
    CommandSpec("device.shutdown", "Shut down device", "Administration", platforms=ALL, destructive=True),
    CommandSpec("device.message", "Message logged-on user", "Administration", platforms=("windows",),
                description="Show a message box to the signed-in user."),
    CommandSpec("service.control", "Start/stop/restart a service", "Administration", needs=("targetPath",), platforms=ALL,
                description="targetPath is the service name; payload action is start, stop or restart."),
    CommandSpec("localadmin.rotate", "Rotate local admin password", "Administration",
                description="Sets a new random local Administrator password; the old one stays in the history."),
    CommandSpec("remote.session.start", "Start remote session", "Remote access", platforms=ALL,
                description="Opened from the Connect button; connects the device to the cloud relay."),
    CommandSpec("remote.session.end", "End remote session", "Remote access", platforms=ALL),
    CommandSpec("patch.scan", "Scan for missing patches", "Patching", platforms=ALL),
    CommandSpec("patch.install", "Install approved patches", "Patching", platforms=ALL,
                description="Installs the patch IDs in the payload, then reboots per the patch policy."),
    CommandSpec("software.install", "Install application", "Software", platforms=ALL,
                description="Installs a package from the software library."),
    CommandSpec("patch.windows.security", "Install security updates", "Patching"),
    CommandSpec("patch.software", "Update third-party software", "Patching"),
    CommandSpec("patch.cycle", "Run full patch cycle", "Patching"),
    CommandSpec("software.search", "Search software", "Software"),
    CommandSpec("software.update", "Update application", "Software", needs=("recordId",)),
    CommandSpec("software.uninstall", "Uninstall application", "Software", needs=("recordId",), platforms=ALL, destructive=True),
    CommandSpec("software.block", "Block application", "Software", needs=("recordId",), permission="configure"),
    CommandSpec("localadmin.audit", "Audit local admins", "Privilege"),
    CommandSpec("localadmin.reduce", "Remove local admins", "Privilege", permission="configure", destructive=True),
    CommandSpec("localadmin.rollback", "Restore local admins", "Privilege", permission="configure"),
    CommandSpec("breakglass.enable", "Enable break-glass admin", "Privilege", permission="configure"),
    CommandSpec("breakglass.disable", "Disable break-glass admin", "Privilege", permission="configure"),
    CommandSpec("update.apply", "Apply agent update", "Agent", permission="configure", platforms=ALL),
    CommandSpec("update.rollback", "Roll back agent update", "Agent", permission="configure"),
    CommandSpec("agent.repair", "Repair agent", "Agent", platforms=ALL),
    CommandSpec("storage.maintenance", "Run storage maintenance", "Agent"),
    CommandSpec("policy.refresh", "Refresh policy now", "Agent", platforms=ALL),
)

BY_TYPE = {spec.type: spec for spec in CATALOG}


def catalog_document() -> list[dict]:
    return [
        {
            "type": spec.type,
            "label": spec.label,
            "group": spec.group,
            "permission": spec.permission,
            "needs": list(spec.needs),
            "platforms": list(spec.platforms),
            "destructive": spec.destructive,
            "description": spec.description,
        }
        for spec in CATALOG
    ]
