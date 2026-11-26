"""Fenrir's automated GRC controls (``grc_library/crosswalk.yml``, FC-*) to ISMS common controls.

From the standalone app's Fenrir connector (ADR 0008), plus FC-SDLC, which Fenrir added later. FC-RISK is not mapped:
risk assessment is an ISMS process, not a control a system check can prove.
"""

FENRIR_CONTROL_MAP: dict[str, tuple[str, ...]] = {
    "FC-ASSET": ("CC-AST-01", "CC-END-01"),
    "FC-MALWARE": ("CC-MAL-01",),
    "FC-WEBFILTER": ("CC-WEB-01",),
    "FC-FIREWALL": ("CC-NET-01",),
    "FC-SECURECONFIG": ("CC-CFG-01",),
    "FC-SCREENLOCK": ("CC-PHY-04",),
    "FC-PATCH": ("CC-VUL-01",),
    "FC-VULN": ("CC-VUL-01",),
    "FC-SUPPORTED": ("CC-VUL-01",),
    "FC-MFA": ("CC-IAM-02",),
    "FC-PRIV": ("CC-IAM-03",),
    "FC-ACCOUNTS": ("CC-IAM-01",),
    "FC-PASSWORDS": ("CC-IAM-02",),
    "FC-APPCONTROL": ("CC-CFG-01",),
    "FC-ENCRYPTION": ("CC-END-01", "CC-CRY-01"),
    "FC-LOGGING": ("CC-LOG-01",),
    "FC-BACKUP": ("CC-BKP-01",),
    "FC-DRTEST": ("CC-BCM-01", "CC-BKP-01"),
    "FC-INCIDENT": ("CC-INC-01",),
    "FC-TRAINING": ("CC-AWR-01",),
    "FC-SUPPLIER": ("CC-SUP-01", "CC-SUP-02"),
    "FC-POLICY": ("CC-GOV-01",),
    "FC-SDLC": ("CC-DEV-01", "CC-DEV-03"),
}
