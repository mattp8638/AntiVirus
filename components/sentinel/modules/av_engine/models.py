from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanMode(str, Enum):
    file = "file"
    directory = "directory"


class AVSeverity(str, Enum):
    clean = "clean"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RemediationMode(str, Enum):
    scan_only = "scan_only"
    quarantine = "quarantine"


class AVScanRequest(BaseModel):
    path: str
    recursive: bool = True
    max_files: int = 5000
    max_file_size_mb: int = 100
    remediation_mode: RemediationMode = RemediationMode.scan_only
    include_ioc_extraction: bool = True
    include_entropy: bool = True
    include_yara: bool = True
    exclusions: List[str] = Field(default_factory=list)


class AVRuleMatch(BaseModel):
    rule_id: str
    name: str
    severity: AVSeverity
    confidence: int = 50
    reason: str
    tactic_id: Optional[str] = None
    technique_id: Optional[str] = None
    source: str = "native"


class AVFileFinding(BaseModel):
    path: str
    filename: str
    extension: str
    size_bytes: int
    sha256: str
    file_type: str
    entropy: Optional[float] = None
    severity: AVSeverity
    verdict: str
    confidence: int
    rule_matches: List[AVRuleMatch] = Field(default_factory=list)
    extracted_iocs: Dict[str, List[str]] = Field(default_factory=dict)
    threat_feed_matches: List[Dict[str, Any]] = Field(default_factory=list)
    yara_matches: List[Dict[str, Any]] = Field(default_factory=list)
    remediation_status: str = "not_applied"
    quarantine_path: Optional[str] = None
    recommended_action: str


class AVScanResponse(BaseModel):
    status: str
    engine: str = "sentinel_native_av"
    target: str
    scanned_files: int
    skipped_files: int
    finding_count: int
    highest_severity: AVSeverity
    remediation_mode: RemediationMode
    findings: List[AVFileFinding] = Field(default_factory=list)
    started_at: str
    completed_at: str
    stored_result: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
