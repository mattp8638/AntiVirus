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
MOBILE = ("android",)

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
    # Windows keeps Volume Shadow Copy snapshots (ransomware.rollbackSnapshots) and records the files an attack changed.
    CommandSpec("ransomware.rollback", "Roll back ransomware changes", "Remediation", platforms=("windows",), destructive=True,
                description="Restores the files changed in the device's last ransomware incident (within 24 hours) from the "
                            "newest snapshot taken before it. Current versions are kept as <name>.fenrir-pre-restore."),
    CommandSpec("threatintel.lookup", "Threat-intel lookup", "Investigation", needs=("targetPath",)),
    CommandSpec("threatintel.pack.ingest", "Push intel pack", "Investigation", permission="configure"),
    CommandSpec("support.bundle", "Collect support bundle", "Investigation", platforms=ALL),
    CommandSpec("support.bundle.sanitized", "Collect sanitised bundle", "Investigation"),
    CommandSpec("forensics.collect", "Collect forensic triage package", "Investigation", platforms=ALL,
                description="Processes, autoruns, network, event logs and prefetch in one archive."),
    CommandSpec("inventory.refresh", "Refresh inventory", "Investigation", platforms=ALL),
    CommandSpec("network.discover", "Discover the local network", "Investigation", platforms=("linux", "macos"),
                description="Interfaces, gateway, neighbours and a short TCP sweep of the device's own private subnets. "
                            "Windows runs the same discovery as a script (Network → Topology)."),
    CommandSpec("pii.scan", "Discover personal data", "Investigation", platforms=("linux", "macos"),
                description="Counts payment cards, NI and NHS numbers, IBANs and emails in users' documents. Only counts and "
                            "file paths are reported. Windows runs the same scan as a script (Vulnerabilities → PII discovery)."),
    CommandSpec("network.probe", "Probe network services", "Investigation", platforms=ALL,
                description="Sent automatically for network monitors that probe from this device; checks TCP services on its LAN."),
    CommandSpec("script.run", "Run script", "Administration", permission="configure", platforms=ALL,
                description="Run a script from the library. Pick it on the Scripts page to fill in parameters."),
    CommandSpec("device.reboot", "Restart device", "Administration", platforms=ALL, destructive=True,
                description="Restart now, or after the delay in the payload (minutes)."),
    CommandSpec("device.shutdown", "Shut down device", "Administration", platforms=ALL, destructive=True),
    CommandSpec("device.message", "Message logged-on user", "Administration", platforms=("windows", "android"),
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
    CommandSpec("localadmin.audit", "Audit local admins", "Privilege",
                description="Lists the members of the local Administrators group."),
    CommandSpec("localadmin.reduce", "Remove local admins", "Privilege", permission="configure", destructive=True,
                description="Removes user accounts from the local Administrators group. Groups, the built-in Administrator, "
                            "the LAPS and break-glass accounts and any names in the payload's keep list stay. Never runs "
                            "on domain controllers."),
    CommandSpec("localadmin.rollback", "Restore local admins", "Privilege", permission="configure",
                description="Puts back every account removed by Remove local admins."),
    CommandSpec("breakglass.enable", "Enable break-glass admin", "Privilege", permission="configure",
                description="Enables the FenrirBreakGlass local administrator for the payload's hours (default 4, max 24). "
                            "Its password is stored first and shown in the device's Local admin tab."),
    CommandSpec("breakglass.disable", "Disable break-glass admin", "Privilege", permission="configure"),
    CommandSpec("elevation.grant", "Grant temporary admin rights", "Privilege", permission="configure",
                description="Sent when an elevation request is approved: adds the user to the local Administrators group "
                            "for the request's minutes."),
    CommandSpec("elevation.revoke", "Revoke temporary admin rights", "Privilege", permission="configure"),
    CommandSpec("update.apply", "Apply agent update", "Agent", permission="configure", platforms=ALL),
    CommandSpec("update.rollback", "Roll back agent update", "Agent", permission="configure"),
    CommandSpec("agent.repair", "Repair agent", "Agent", platforms=ALL),
    CommandSpec("storage.maintenance", "Run storage maintenance", "Agent"),
    CommandSpec("policy.refresh", "Refresh policy now", "Agent", platforms=ALL + MOBILE),
    # Phones (the Android agent). Lost mode is set from the Location tab, which records it on the device too.
    CommandSpec("device.locate", "Locate now", "Phone", platforms=MOBILE,
                description="Asks the phone for a fresh location fix; it appears on the Location tab within a minute."),
    CommandSpec("device.lock", "Lock the phone", "Phone", platforms=MOBILE,
                description="Locks the screen now; the user needs their PIN, pattern or fingerprint to get back in."),
    CommandSpec("device.alarm", "Play alarm", "Phone", platforms=MOBILE,
                description="Plays a loud alarm at full volume, even in silent mode, for the payload's seconds (default 60)."),
    CommandSpec("device.lostmode", "Lost mode", "Phone", platforms=MOBILE,
                description="Locks the phone, shows your message and phone number on the screen and reports its "
                            "location every 5 minutes until lost mode is turned off. Use the Location tab."),
    CommandSpec("device.wipe", "Erase the phone", "Phone", permission="configure", platforms=MOBILE, destructive=True,
                description="Factory-resets the phone. Everything on it is deleted and it stops reporting. Asks for your "
                            "password again."),
)

BY_TYPE = {spec.type: spec for spec in CATALOG}
# Sent by a person from the device page only: never from automations, monitors, bulk actions or the API's batch paths.
INTERACTIVE_ONLY = {"device.wipe", "device.lostmode"}


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
