"""The protection policy schema, templates, layering, and agent translation.

Every setting is declared once in ``SCHEMA``. From that single declaration we
derive the defaults, input validation, the console's policy editor, and the
flattened document each agent receives.

Layering (most general first):

    template defaults -> global policy -> tenant policy -> group policy chain -> device override

Each layer stores only the keys it changes. A layer can also *lock* a dotted
key, after which lower layers cannot override it (ESET calls this "force").
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Field declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class F:
    key: str
    kind: str  # bool | int | enum | list | str
    default: Any
    label: str
    help: str = ""
    min: int | None = None
    max: int | None = None
    options: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ("windows", "linux", "macos")


@dataclass(frozen=True)
class Section:
    key: str
    title: str
    description: str
    fields: tuple[F, ...] = field(default_factory=tuple)


ASR_RULES = (
    ("blockOfficeChildProcesses", "Block Office apps from creating child processes"),
    ("blockOfficeExecutableContent", "Block Office apps from writing executable content"),
    ("blockOfficeCodeInjection", "Block Office apps from injecting code into other processes"),
    ("blockObfuscatedScripts", "Block potentially obfuscated scripts"),
    ("blockScriptDownloadedPayloads", "Block JavaScript/VBScript launching downloaded executables"),
    ("blockEmailExecutables", "Block executable content from email and webmail"),
    ("blockCredentialStealingLsass", "Block credential stealing from LSASS"),
    ("blockPsexecWmiProcessCreation", "Block process creation from PsExec and WMI commands"),
    ("blockUntrustedUsbProcesses", "Block untrusted and unsigned processes that run from USB"),
    ("blockWmiPersistence", "Block persistence through WMI event subscription"),
    ("blockVulnerableSignedDrivers", "Block abuse of exploited vulnerable signed drivers"),
    ("blockLolbinAbuse", "Block living-off-the-land binary abuse (certutil, mshta, regsvr32, rundll32)"),
    ("blockAdobeReaderChildProcesses", "Block Adobe Reader from creating child processes"),
    ("blockWebshellCreation", "Block webshell creation on servers"),
    ("advancedRansomwareProtection", "Use advanced protection against ransomware"),
)

DNS_CATEGORIES = (
    "malware",
    "phishing",
    "command-and-control",
    "cryptomining",
    "newly-registered",
    "parked",
    "dga",
    "adult",
    "gambling",
    "piracy",
    "ads-trackers",
    "social-media",
    "streaming",
    "games",
    "dating",
    "proxies-vpn",
    "doh-bypass",
)

ASR_MODES = ("off", "audit", "warn", "block")

SCHEMA: tuple[Section, ...] = (
    Section(
        "antimalware",
        "Anti-malware engine",
        "Signature, heuristic, machine-learning and cloud reputation scanning.",
        (
            F("realtimeProtection", "bool", True, "Real-time protection", "Scan files on open, write and execute."),
            F("cloudLookup", "bool", True, "Cloud reputation lookups", "Ask Fenrir Cloud about unknown hashes and URLs."),
            F("cloudLookupObserveOnly", "bool", False, "Cloud verdicts observe-only", "Log cloud verdicts without acting on them."),
            F("scriptInspection", "bool", True, "Script and memory inspection (AMSI)", platforms=("windows",)),
            F("quarantineOnMalicious", "bool", True, "Quarantine malicious files"),
            F("mlSensitivity", "enum", "balanced", "Machine-learning sensitivity",
              "Higher catches more unknown malware with more false positives.",
              options=("off", "cautious", "balanced", "aggressive", "paranoid")),
            F("puaProtection", "enum", "block", "Potentially unwanted apps", options=("off", "audit", "block")),
            F("scanArchives", "bool", True, "Scan inside archives"),
            F("archiveObserveOnly", "bool", False, "Archive detections observe-only"),
            F("archiveMaxDepth", "int", 5, "Archive nesting depth", min=1, max=20),
            F("scanRemovableMedia", "bool", True, "Scan removable media on insert"),
            F("scanNetworkDrives", "bool", False, "Scan mapped network drives"),
            F("scanMaliciousBlockThreshold", "int", 45, "On-demand block score", min=1, max=99),
            F("scanMaliciousQuarantineThreshold", "int", 70, "On-demand quarantine score", min=1, max=99),
            F("scanBenignDampeningScore", "int", 20, "Benign evidence dampening", min=0, max=80),
            F("genericRuleScoreScalePercent", "int", 75, "Generic rule weight (%)", min=20, max=100),
            F("realtimeExecuteBlockThreshold", "int", 55, "Real-time execute block score", min=40, max=99),
            F("realtimeNonExecuteBlockThreshold", "int", 60, "Real-time open/write block score", min=50, max=99),
            F("realtimeQuarantineThreshold", "int", 75, "Real-time quarantine score", min=40, max=99),
            F("realtimeObserveTelemetryThreshold", "int", 35, "Telemetry-only score", min=1, max=95),
            F("realtimeObserveOnlyForNonExecute", "bool", False, "Only observe non-execute access"),
            F("enableCleanwareSignerDampening", "bool", True, "Trust known clean publishers"),
            F("enableKnownGoodHashDampening", "bool", True, "Trust known-good hashes"),
            F("quickScanSchedule", "str", "daily 12:30", "Quick scan schedule", "e.g. 'daily 12:30', 'weekdays 09:00', 'off'."),
            F("fullScanSchedule", "str", "weekly sun 02:00", "Full scan schedule"),
            F("scanCpuLimitPercent", "int", 50, "Scheduled scan CPU limit (%)", min=5, max=100),
            F("exclusionPaths", "list", [], "Excluded paths", "Folder roots to skip. Prefer hashes or signers where possible."),
            F("exclusionSha256", "list", [], "Excluded SHA-256 hashes"),
            F("exclusionSigners", "list", [], "Excluded publishers (signer names)"),
            F("exclusionProcesses", "list", [], "Excluded processes", "Files opened by these processes are not scanned."),
            F("requireSignerForSuppression", "bool", False, "Path exclusions only for signed files"),
            F("allowUnsignedSuppressionPathExecutables", "bool", False, "Allow unsigned executables in excluded paths"),
        ),
    ),
    Section(
        "edr",
        "EDR and behaviour",
        "Behavioural detection, process control, exploit and credential protection.",
        (
            F("enabled", "bool", True, "Behavioural monitoring"),
            F("enforceProcessStartVerdicts", "bool", True, "Block malicious process starts"),
            F("terminateProcessTreeOnExecuteBlock", "bool", True, "Kill the whole process tree on block"),
            F("quarantineAfterProcessKill", "bool", True, "Quarantine the image after killing it"),
            F("memoryScanning", "bool", True, "Advanced memory scanner", "Scan process memory after unpacking/injection."),
            F("exploitProtection", "bool", True, "Exploit blocker", "Watch browsers, Office, PDF readers and Java for exploitation."),
            F("credentialProtection", "bool", True, "Credential theft protection", "Protect LSASS and browser credential stores."),
            F("deceptionLures", "bool", False, "Deception lures", "Plant fake credentials and files that alert on touch."),
            F("telemetryLevel", "enum", "standard", "Telemetry level", options=("minimal", "standard", "verbose")),
            F("collectProcessEvents", "bool", True, "Collect process events"),
            F("collectNetworkEvents", "bool", True, "Collect network events"),
            F("collectFileEvents", "bool", True, "Collect file events"),
            F("collectRegistryEvents", "bool", True, "Collect registry events", platforms=("windows",)),
            F("collectDnsEvents", "bool", True, "Collect DNS events"),
            F("collectScriptEvents", "bool", True, "Collect script content (AMSI/PowerShell)", platforms=("windows",)),
            F("telemetryUploadSeconds", "int", 30, "Telemetry upload interval (s)", min=5, max=3600),
            F("failServiceStartupIfRealtimeCoverageMissing", "bool", True, "Fail closed if real-time coverage is missing", platforms=("windows",)),
            F("requireMinifilterBrokerConnection", "bool", True, "Require the file-system minifilter", platforms=("windows",)),
        ),
    ),
    Section(
        "attackSurface",
        "Attack surface reduction",
        "Per-rule control of common initial-access and lateral-movement techniques.",
        tuple(F(key, "enum", "block" if key not in {"blockPsexecWmiProcessCreation", "blockWebshellCreation"} else "audit",
                label, options=ASR_MODES) for key, label in ASR_RULES),
    ),
    Section(
        "ransomware",
        "Ransomware protection",
        "Behavioural encryption detection, protected folders, canaries and rollback.",
        (
            F("enabled", "bool", True, "Ransomware shield"),
            F("mode", "enum", "block", "Response", options=("audit", "block", "block-and-rollback")),
            F("massEncryptionFilesPerMinute", "int", 40, "Files changed per minute that trigger detection", min=5, max=1000),
            F("entropyDetection", "bool", True, "High-entropy write detection"),
            F("canaryFiles", "bool", True, "Canary (honey) files"),
            F("blockShadowCopyDeletion", "bool", True, "Block shadow copy and backup deletion"),
            F("protectedFolders", "list", ["%USERPROFILE%\\Documents", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Pictures"],
              "Protected folders", "Only allowed apps may modify these folders."),
            F("protectedFoldersMode", "enum", "audit", "Protected folder enforcement", options=("off", "audit", "block")),
            F("allowedApps", "list", [], "Apps allowed into protected folders"),
            F("rollbackSnapshots", "bool", True, "Keep rollback snapshots (VSS / btrfs / APFS)"),
            F("snapshotIntervalHours", "int", 4, "Snapshot interval (hours)", min=1, max=72),
            F("networkShareProtection", "bool", True, "Detect remote encryption over SMB"),
        ),
    ),
    Section(
        "web",
        "Web and phishing protection",
        "Destination reputation for browsers, email links and every process.",
        (
            F("destinationProtectionEnabled", "bool", True, "Destination reputation"),
            F("antiPhishingEnabled", "bool", True, "Anti-phishing"),
            F("webProtectionEnabled", "bool", True, "Web protection"),
            F("emailLinkProtectionEnabled", "bool", True, "Email link protection"),
            F("evaluateDomains", "bool", True, "Evaluate domains"),
            F("evaluateUrls", "bool", True, "Evaluate full URLs"),
            F("blockKnownMaliciousDestinations", "bool", True, "Block malicious destinations"),
            F("blockKnownPhishingDestinations", "bool", True, "Block phishing destinations"),
            F("blockKnownScamDestinations", "bool", False, "Block scam destinations"),
            F("warnOnSuspiciousDestinations", "bool", True, "Warn on suspicious destinations"),
            F("warnOnNewlyRegisteredDomains", "bool", True, "Warn on newly registered domains"),
            F("networkObserveOnly", "bool", False, "Network verdicts observe-only"),
            F("allowDegradedDestinationModeWhenOffline", "bool", True, "Fall back to local lists when offline"),
            F("browserContextRequiredForWarnOnly", "bool", False, "Only warn inside browsers"),
            F("suspiciousDestinationWarnThreshold", "int", 45, "Suspicious warn score", min=1, max=99),
            F("phishingWarnThreshold", "int", 55, "Phishing warn score", min=1, max=99),
            F("phishingBlockThreshold", "int", 80, "Phishing block score", min=1, max=99),
            F("destinationCacheTtlMinutes", "int", 240, "Verdict cache (minutes)", min=5, max=10080),
            F("bankingProtection", "bool", True, "Secure browser for banking and payments", platforms=("windows",)),
        ),
    ),
    Section(
        "dns",
        "DNS protection",
        "Encrypted DNS filtering through Fenrir Cloud, on and off the corporate network.",
        (
            F("enabled", "bool", True, "DNS filtering"),
            F("mode", "enum", "agent-doh", "Delivery", "agent-doh routes the device's DNS through its own DoH URL.",
              options=("agent-doh", "network-resolver", "observe")),
            F("blockedCategories", "list", ["malware", "phishing", "command-and-control", "cryptomining", "dga", "doh-bypass"],
              "Blocked categories", options=DNS_CATEGORIES),
            F("blockAction", "enum", "sinkhole", "Block response", options=("sinkhole", "nxdomain", "refused")),
            F("allowDomains", "list", [], "Always allow"),
            F("blockDomains", "list", [], "Always block"),
            F("safeSearch", "bool", False, "Enforce SafeSearch"),
            F("blockThirdPartyDoh", "bool", True, "Block third-party encrypted DNS (DoH/DoT bypass)"),
            F("logQueries", "enum", "blocked", "Query logging", options=("none", "blocked", "all")),
        ),
    ),
    Section(
        "firewall",
        "Firewall and network attack protection",
        "Host firewall, IDS signatures, and isolation behaviour.",
        (
            F("enabled", "bool", True, "Managed firewall"),
            F("defaultInbound", "enum", "block", "Default inbound", options=("allow", "block")),
            F("defaultOutbound", "enum", "allow", "Default outbound", options=("allow", "block")),
            F("networkAttackProtection", "bool", True, "Network attack protection (IDS)"),
            F("botnetProtection", "bool", True, "Botnet / C2 callback blocking"),
            F("bruteForceProtection", "bool", True, "Block RDP/SMB/SSH brute force"),
            F("blockSmbV1", "bool", True, "Block SMBv1", platforms=("windows",)),
            F("blockLlmnrNetbios", "bool", True, "Block LLMNR and NetBIOS poisoning", platforms=("windows",)),
            F("rules", "list", [], "Custom rules", "Lines like 'allow in tcp 3389 from 10.0.0.0/8'."),
            F("networkContainment", "bool", True, "Allow remote network isolation"),
            F("isolationAllowlist", "list", [], "Reachable while isolated", "Hosts/CIDRs still reachable during isolation."),
        ),
    ),
    Section(
        "deviceControl",
        "Device control",
        "USB, Bluetooth, optical and printer access.",
        (
            F("enabled", "bool", True, "Device control"),
            F("usbStorage", "enum", "allow", "USB storage", options=("allow", "audit", "read-only", "block")),
            F("usbAllowedIds", "list", [], "Allowed USB device IDs", "VID:PID or serial."),
            F("encryptedUsbOnly", "bool", False, "Only allow encrypted USB drives"),
            F("bluetoothFileTransfer", "enum", "allow", "Bluetooth file transfer", options=("allow", "audit", "block")),
            F("opticalMedia", "enum", "allow", "CD/DVD", options=("allow", "read-only", "block")),
            F("mtpDevices", "enum", "allow", "Phones and cameras (MTP)", options=("allow", "read-only", "block")),
            F("printing", "enum", "allow", "Printing", options=("allow", "audit", "block")),
        ),
    ),
    Section(
        "applicationControl",
        "Application control",
        "Allow/deny execution by publisher, hash, path or reputation.",
        (
            F("mode", "enum", "off", "Mode", options=("off", "audit", "enforce-denylist", "enforce-allowlist")),
            F("blockedApps", "list", [], "Blocked apps", "Names, hashes or publisher names."),
            F("allowedPublishers", "list", ["Microsoft Windows", "Microsoft Corporation"], "Trusted publishers"),
            F("allowedHashes", "list", [], "Trusted hashes"),
            F("blockUnknownReputation", "bool", False, "Block apps with no reputation"),
            F("blockNewlySeenExecutables", "bool", False, "Block executables first seen in the last 24h"),
        ),
    ),
    Section(
        "privilege",
        "Privilege management",
        "Least-privilege controls with just-in-time elevation (PAM).",
        (
            F("enabled", "bool", False, "Privilege management"),
            F("removeLocalAdmins", "bool", False, "Remove standing local admin rights"),
            F("elevationRequests", "enum", "approval", "Elevation requests", options=("off", "auto-approve", "approval")),
            F("elevationMinutes", "int", 30, "Elevation length (minutes)", min=5, max=480),
            F("autoApprovePublishers", "list", [], "Auto-approve signed by"),
            F("breakGlassAllowed", "bool", True, "Allow break-glass admin"),
            F("rotateLocalAdminPassword", "bool", True, "Rotate the local admin password (LAPS)", platforms=("windows",)),
        ),
    ),
    Section(
        "patch",
        "Patch and vulnerability management",
        "Operating system and third-party patching, prioritised by exploitability.",
        (
            F("enabled", "bool", True, "Patch management"),
            F("autoApprove", "enum", "security", "Auto-approve", options=("none", "critical", "security", "all")),
            F("thirdPartyApps", "bool", True, "Patch third-party apps"),
            F("prioritiseKnownExploited", "bool", True, "Fast-track known-exploited (KEV) fixes"),
            F("deferralDaysCritical", "int", 0, "Defer critical (days)", min=0, max=30),
            F("deferralDaysOther", "int", 7, "Defer others (days)", min=0, max=90),
            F("maintenanceWindow", "str", "daily 22:00-05:00", "Maintenance window"),
            F("rebootBehaviour", "enum", "prompt", "Reboots", options=("never", "prompt", "outside-hours", "force")),
            F("vulnerabilityScanHours", "int", 24, "Vulnerability scan interval (hours)", min=1, max=168),
        ),
    ),
    Section(
        "tamper",
        "Tamper protection",
        "Stop users and malware from disabling protection.",
        (
            F("enabled", "bool", True, "Tamper protection"),
            F("uninstallRequiresToken", "bool", True, "Uninstall needs a cloud token"),
            F("protectServiceAndFiles", "bool", True, "Protect service, files and registry"),
            F("selfDefenceSensitivity", "enum", "high", "Self-defence", options=("standard", "high")),
        ),
    ),
    Section(
        "response",
        "Automated response",
        "What the agent and cloud do without waiting for an analyst.",
        (
            F("autoIsolateOnCritical", "bool", False, "Isolate the device on critical incidents"),
            F("autoKillOnHigh", "bool", True, "Kill malicious processes on high alerts"),
            F("autoQuarantine", "bool", True, "Quarantine artefacts automatically"),
            F("autoRollbackRansomware", "bool", True, "Roll back ransomware changes automatically"),
            F("autoOpenTicket", "enum", "high", "Open a PSA ticket from", options=("off", "low", "medium", "high", "critical")),
            F("remoteShell", "bool", False, "Allow remote shell for analysts"),
            F("scriptExecution", "bool", True, "Allow approved remote scripts"),
        ),
    ),
    Section(
        "experience",
        "End-user experience",
        "What people at the device see and can do.",
        (
            F("trayIcon", "bool", True, "Show tray icon"),
            F("notifications", "enum", "important", "Notifications", options=("none", "important", "all")),
            F("allowUserScans", "bool", True, "Users can run scans"),
            F("allowUserPause", "bool", False, "Users can pause protection"),
            F("allowQuarantineRestore", "bool", False, "Users can restore from quarantine"),
            F("brandName", "str", "Fenrir", "Brand name", "White-label the agent UI."),
            F("supportContact", "str", "", "Support contact shown to users"),
            F("language", "enum", "auto", "Language", options=("auto", "en", "de", "fr", "es", "it", "nl", "pl", "pt")),
        ),
    ),
    Section(
        "updates",
        "Updates",
        "Agent, engine and signature update rings.",
        (
            F("channel", "enum", "stable", "Release ring", options=("canary", "beta", "stable", "lts")),
            F("autoUpdateAgent", "bool", True, "Update agent automatically"),
            F("signatureIntervalMinutes", "int", 60, "Signature check interval (minutes)", min=5, max=1440),
            F("peerCaching", "bool", True, "Share updates between devices on the LAN"),
        ),
    ),
)

SECTIONS = {section.key: section for section in SCHEMA}
FIELDS = {f"{section.key}.{f.key}": f for section in SCHEMA for f in section.fields}


def defaults() -> dict:
    return {section.key: {f.key: copy.deepcopy(f.default) for f in section.fields} for section in SCHEMA}


# ---------------------------------------------------------------------------
# Templates: starting points that only list what differs from defaults.
# ---------------------------------------------------------------------------

TEMPLATES: dict[str, dict[str, Any]] = {
    "balanced": {
        "_label": "Balanced (recommended)",
        "_description": "Strong protection with low friction. Right for most businesses.",
    },
    "home": {
        "_label": "Home and family",
        "_description": "Consumer-friendly: adult/gambling DNS blocking, simple notifications.",
        "dns": {"blockedCategories": ["malware", "phishing", "command-and-control", "cryptomining", "dga", "adult", "gambling"],
                "safeSearch": True},
        "experience": {"allowUserPause": True, "allowQuarantineRestore": True},
        "patch": {"rebootBehaviour": "prompt"},
    },
    "strict": {
        "_label": "Strict / high security",
        "_description": "Regulated industries. Aggressive ML, USB read-only, privilege management on.",
        "antimalware": {"mlSensitivity": "aggressive", "scanNetworkDrives": True, "realtimeExecuteBlockThreshold": 50},
        "edr": {"telemetryLevel": "verbose", "deceptionLures": True},
        "attackSurface": {key: "block" for key, _ in ASR_RULES},
        "ransomware": {"mode": "block-and-rollback", "protectedFoldersMode": "block"},
        "dns": {"blockedCategories": ["malware", "phishing", "command-and-control", "cryptomining", "dga", "newly-registered",
                                      "parked", "proxies-vpn", "doh-bypass", "piracy"]},
        "deviceControl": {"usbStorage": "read-only", "encryptedUsbOnly": True, "bluetoothFileTransfer": "block"},
        "applicationControl": {"mode": "enforce-denylist", "blockUnknownReputation": True},
        "privilege": {"enabled": True, "removeLocalAdmins": True},
        "response": {"autoIsolateOnCritical": True, "autoOpenTicket": "medium"},
        "web": {"blockKnownScamDestinations": True},
    },
    "lockdown": {
        "_label": "Lockdown / kiosk",
        "_description": "Allow-list only. For kiosks, POS terminals and single-purpose machines.",
        "applicationControl": {"mode": "enforce-allowlist", "blockUnknownReputation": True, "blockNewlySeenExecutables": True},
        "deviceControl": {"usbStorage": "block", "bluetoothFileTransfer": "block", "opticalMedia": "block", "mtpDevices": "block"},
        "firewall": {"defaultOutbound": "block"},
        "experience": {"trayIcon": False, "notifications": "none", "allowUserScans": False},
        "privilege": {"enabled": True, "removeLocalAdmins": True, "elevationRequests": "off"},
    },
    "server": {
        "_label": "Server",
        "_description": "Tuned for servers: low CPU scans, webshell blocking, no user prompts.",
        "antimalware": {"scanCpuLimitPercent": 25, "quickScanSchedule": "daily 03:00", "scanRemovableMedia": False},
        "attackSurface": {"blockWebshellCreation": "block", "blockPsexecWmiProcessCreation": "audit"},
        "experience": {"trayIcon": False, "notifications": "none"},
        "patch": {"rebootBehaviour": "never", "autoApprove": "critical"},
        "ransomware": {"networkShareProtection": True, "snapshotIntervalHours": 2},
    },
    "developer": {
        "_label": "Developer workstation",
        "_description": "Fewer false positives for build tools and scripting.",
        "antimalware": {"mlSensitivity": "cautious", "exclusionProcesses": ["node.exe", "dotnet.exe", "cargo.exe", "go.exe", "python.exe"]},
        "attackSurface": {"blockObfuscatedScripts": "audit", "blockLolbinAbuse": "audit"},
    },
    "audit": {
        "_label": "Audit only (evaluation)",
        "_description": "Detect and report everything, block nothing. Use for proof-of-value or migrations.",
        "antimalware": {"quarantineOnMalicious": False, "cloudLookupObserveOnly": True, "archiveObserveOnly": True,
                        "realtimeObserveOnlyForNonExecute": True, "puaProtection": "audit"},
        "edr": {"enforceProcessStartVerdicts": False, "terminateProcessTreeOnExecuteBlock": False, "quarantineAfterProcessKill": False},
        "attackSurface": {key: "audit" for key, _ in ASR_RULES},
        "ransomware": {"mode": "audit", "protectedFoldersMode": "audit"},
        "web": {"networkObserveOnly": True},
        "dns": {"mode": "observe"},
        "response": {"autoKillOnHigh": False, "autoQuarantine": False, "autoRollbackRansomware": False},
    },
}


def template_settings(name: str) -> dict:
    template = TEMPLATES.get(name, TEMPLATES["balanced"])
    return {key: value for key, value in template.items() if not key.startswith("_")}


# ---------------------------------------------------------------------------
# Validation and merging
# ---------------------------------------------------------------------------


class PolicyError(ValueError):
    pass


def _coerce(path: str, spec: F, value: Any) -> Any:
    if spec.kind == "bool":
        if not isinstance(value, bool):
            raise PolicyError(f"{path} must be true or false")
        return value
    if spec.kind == "int":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise PolicyError(f"{path} must be a number")
        value = int(value)
        if spec.min is not None and value < spec.min or spec.max is not None and value > spec.max:
            raise PolicyError(f"{path} must be between {spec.min} and {spec.max}")
        return value
    if spec.kind == "enum":
        if value not in spec.options:
            raise PolicyError(f"{path} must be one of {', '.join(spec.options)}")
        return value
    if spec.kind == "list":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise PolicyError(f"{path} must be a list of strings")
        cleaned = [item.strip() for item in value if item.strip()]
        if spec.options:
            bad = [item for item in cleaned if item not in spec.options]
            if bad:
                raise PolicyError(f"{path} has unknown values: {', '.join(bad)}")
        return cleaned
    if spec.kind == "str":
        if not isinstance(value, str):
            raise PolicyError(f"{path} must be text")
        return value[:500]
    raise PolicyError(f"{path} has unsupported type")  # pragma: no cover


def validate_partial(settings: dict) -> dict:
    """Validate a sparse layer and return a cleaned copy. Unknown keys are rejected."""
    if not isinstance(settings, dict):
        raise PolicyError("settings must be an object")
    cleaned: dict = {}
    for section_key, values in settings.items():
        section = SECTIONS.get(section_key)
        if section is None:
            raise PolicyError(f"unknown section '{section_key}'")
        if not isinstance(values, dict):
            raise PolicyError(f"{section_key} must be an object")
        for key, value in values.items():
            path = f"{section_key}.{key}"
            spec = FIELDS.get(path)
            if spec is None:
                raise PolicyError(f"unknown setting '{path}'")
            cleaned.setdefault(section_key, {})[key] = _coerce(path, spec, value)
    return cleaned


def validate_locks(locks: list) -> list[str]:
    if not isinstance(locks, list):
        raise PolicyError("locks must be a list")
    bad = [lock for lock in locks if lock not in FIELDS and lock not in SECTIONS]
    if bad:
        raise PolicyError(f"unknown lock keys: {', '.join(bad)}")
    return sorted(set(locks))


def _is_locked(path: str, locked: set[str]) -> bool:
    return path in locked or path.split(".", 1)[0] in locked


@dataclass
class Layer:
    name: str
    settings: dict
    locks: list[str] = field(default_factory=list)


def resolve(layers: list[Layer]) -> dict:
    """Merge layers (most general first). Returns settings plus provenance.

    ``origin`` tells the console which layer set each value, and ``locked``
    which layer locked it, so admins can see why a device behaves as it does.
    """
    effective = defaults()
    origin = {path: "default" for path in FIELDS}
    locked_by: dict[str, str] = {}
    blocked: list[dict] = []

    for layer in layers:
        for section_key, values in layer.settings.items():
            for key, value in values.items():
                path = f"{section_key}.{key}"
                if path not in FIELDS:
                    continue
                if _is_locked(path, set(locked_by)):
                    blocked.append({"setting": path, "layer": layer.name, "lockedBy": locked_by.get(path) or locked_by.get(section_key)})
                    continue
                effective[section_key][key] = copy.deepcopy(value)
                origin[path] = layer.name
        for lock in layer.locks:
            locked_by.setdefault(lock, layer.name)

    return {"settings": effective, "origin": origin, "locked": locked_by, "overridesBlocked": blocked}


def revision(settings: dict) -> str:
    canonical = json.dumps(settings, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Agent translation
# ---------------------------------------------------------------------------


def to_agent_policy(policy_id: str, name: str, settings: dict) -> dict:
    """Translate effective settings into the document agents parse.

    The top-level keys are exactly what the Windows service's
    ``ParsePolicySnapshot`` reads. Newer modules ride along under ``modules``
    so older agents ignore them safely and newer agents can opt in.
    """
    am, edr, web, fw = settings["antimalware"], settings["edr"], settings["web"], settings["firewall"]
    doc = {
        "id": policy_id,
        "name": name,
        "revision": revision(settings),
        "realtimeProtection": am["realtimeProtection"],
        "cloudLookup": am["cloudLookup"],
        "scriptInspection": am["scriptInspection"],
        "networkContainment": fw["networkContainment"],
        "quarantineOnMalicious": am["quarantineOnMalicious"],
        "suppressionPathRoots": am["exclusionPaths"],
        "suppressionSha256": [value.lower() for value in am["exclusionSha256"]],
        "suppressionSignerNames": am["exclusionSigners"],
    }
    for key in (
        "scanMaliciousBlockThreshold", "scanMaliciousQuarantineThreshold", "scanBenignDampeningScore",
        "genericRuleScoreScalePercent", "realtimeExecuteBlockThreshold", "realtimeNonExecuteBlockThreshold",
        "realtimeQuarantineThreshold", "realtimeObserveTelemetryThreshold", "realtimeObserveOnlyForNonExecute",
        "archiveObserveOnly", "cloudLookupObserveOnly", "requireSignerForSuppression",
        "allowUnsignedSuppressionPathExecutables", "enableCleanwareSignerDampening", "enableKnownGoodHashDampening",
    ):
        doc[key] = am[key]
    for key in (
        "terminateProcessTreeOnExecuteBlock", "enforceProcessStartVerdicts", "quarantineAfterProcessKill",
        "failServiceStartupIfRealtimeCoverageMissing", "requireMinifilterBrokerConnection",
    ):
        doc[key] = edr[key]
    for key, value in web.items():
        if key != "bankingProtection":
            doc[key] = value
    # Agents enforce the quarantine threshold as >= block threshold; keep them consistent.
    doc["scanMaliciousQuarantineThreshold"] = max(doc["scanMaliciousQuarantineThreshold"], doc["scanMaliciousBlockThreshold"])
    doc["realtimeQuarantineThreshold"] = max(
        doc["realtimeQuarantineThreshold"], doc["realtimeExecuteBlockThreshold"], doc["realtimeNonExecuteBlockThreshold"]
    )
    doc["modules"] = {
        key: value for key, value in settings.items() if key not in {"antimalware", "web"}
    }
    doc["modules"]["antimalware"] = {
        key: am[key] for key in ("mlSensitivity", "puaProtection", "scanArchives", "archiveMaxDepth", "scanRemovableMedia",
                                 "scanNetworkDrives", "quickScanSchedule", "fullScanSchedule", "scanCpuLimitPercent",
                                 "exclusionProcesses")
    }
    return doc


def schema_document() -> dict:
    """The schema as JSON for the console's generated policy editor."""
    return {
        "sections": [
            {
                "key": section.key,
                "title": section.title,
                "description": section.description,
                "fields": [
                    {
                        "key": f.key,
                        "path": f"{section.key}.{f.key}",
                        "kind": f.kind,
                        "default": f.default,
                        "label": f.label,
                        "help": f.help,
                        "min": f.min,
                        "max": f.max,
                        "options": list(f.options),
                        "platforms": list(f.platforms),
                    }
                    for f in section.fields
                ],
            }
            for section in SCHEMA
        ],
        "templates": [
            {"key": key, "label": value["_label"], "description": value["_description"]} for key, value in TEMPLATES.items()
        ],
        "fieldCount": len(FIELDS),
    }
