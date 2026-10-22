import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Tuple

from .entropy import shannon_entropy
from .extractors import extract_iocs
from .feeds import lookup_feed_matches
from .filetypes import detect_file_type, risky_extension
from .hashing import sha256_file
from .models import AVFileFinding, AVRuleMatch, AVScanRequest, AVScanResponse, AVSeverity, RemediationMode
from .quarantine import quarantine_file
from .rules import match_native_rules, rule_pack_status
from .yara_adapter import scan_yara, yara_available

RESULTS_DIR = Path("data") / "native_av_scans"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_SCORE = {
    AVSeverity.clean: 0,
    AVSeverity.low: 1,
    AVSeverity.medium: 2,
    AVSeverity.high: 3,
    AVSeverity.critical: 4,
}


def now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def should_exclude(path: Path, exclusions: List[str]) -> bool:
    value = str(path).lower()
    return any(exclusion.lower() in value for exclusion in exclusions if exclusion)


def iter_targets(request: AVScanRequest) -> Tuple[Iterable[Path], int]:
    root = Path(request.path)
    if root.is_file():
        return [root], 0
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {request.path}")
    if not root.is_dir():
        raise ValueError(f"Target is not a file or directory: {request.path}")
    pattern = "**/*" if request.recursive else "*"
    files = []
    skipped = 0
    for item in root.glob(pattern):
        if not item.is_file():
            continue
        if should_exclude(item, request.exclusions):
            skipped += 1
            continue
        files.append(item)
        if len(files) >= request.max_files:
            break
    return files, skipped


def highest(matches: List[AVRuleMatch], feed_matches: list, yara_matches: list, entropy: float | None, risky_ext: bool) -> Tuple[AVSeverity, int, str]:
    severity = AVSeverity.clean
    confidence = 0
    reasons = []
    for match in matches:
        if SEVERITY_SCORE[match.severity] > SEVERITY_SCORE[severity]:
            severity = match.severity
        confidence = max(confidence, match.confidence)
        reasons.append(match.reason)
    if feed_matches:
        severity = AVSeverity.critical
        confidence = max(confidence, 95)
        reasons.append("File hash or embedded IOC matched the local threat feed.")
    if yara_matches:
        severity = AVSeverity.high if severity != AVSeverity.critical else severity
        confidence = max(confidence, 85)
        reasons.append("YARA rule match was returned.")
    if entropy is not None and entropy >= 7.2 and risky_ext:
        severity = AVSeverity.medium if SEVERITY_SCORE[severity] < SEVERITY_SCORE[AVSeverity.medium] else severity
        confidence = max(confidence, 55)
        reasons.append("High entropy in a risky file type may indicate packing, encryption or obfuscation.")
    if risky_ext and severity == AVSeverity.clean:
        severity = AVSeverity.low
        confidence = max(confidence, 30)
        reasons.append("Risky executable/script/archive extension observed.")
    if severity == AVSeverity.clean:
        return severity, 0, "No suspicious rules, feeds or heuristics matched."
    return severity, confidence, " ".join(reasons[:3])


def recommended_action(severity: AVSeverity, remediation_mode: RemediationMode) -> str:
    if severity in {AVSeverity.critical, AVSeverity.high}:
        if remediation_mode == RemediationMode.quarantine:
            return "Review the quarantined file, preserve evidence, and investigate related process/user activity."
        return "Treat as suspicious. Preserve evidence, avoid executing the file, and investigate related endpoint activity."
    if severity == AVSeverity.medium:
        return "Review the file context, publisher, source path and related user activity before allowing execution."
    if severity == AVSeverity.low:
        return "Low-risk indicator only. Review if unexpected or found in a sensitive location."
    return "No action required unless other telemetry indicates suspicious behaviour."


def scan_file(path: Path, request: AVScanRequest) -> AVFileFinding:
    size = path.stat().st_size
    sha256_value = sha256_file(path)
    file_type = detect_file_type(path)
    entropy = shannon_entropy(path) if request.include_entropy else None
    extracted = extract_iocs(path) if request.include_ioc_extraction else {"urls": [], "ips": [], "domains": []}
    native_matches = match_native_rules(path)
    feed_matches = lookup_feed_matches(sha256_value, extracted)
    yara_matches = scan_yara(path) if request.include_yara else []
    severity, confidence, verdict = highest(native_matches, feed_matches, yara_matches, entropy, risky_extension(path))
    remediation_status = "not_applied"
    quarantine_path = None
    if severity in {AVSeverity.high, AVSeverity.critical} and request.remediation_mode == RemediationMode.quarantine:
        try:
            quarantine_path = quarantine_file(path, sha256_value)
            remediation_status = "quarantined"
        except Exception as exc:
            remediation_status = f"quarantine_failed: {exc}"
    return AVFileFinding(
        path=str(path),
        filename=path.name,
        extension=path.suffix.lower(),
        size_bytes=size,
        sha256=sha256_value,
        file_type=file_type,
        entropy=entropy,
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        rule_matches=native_matches,
        extracted_iocs=extracted,
        threat_feed_matches=feed_matches,
        yara_matches=yara_matches,
        remediation_status=remediation_status,
        quarantine_path=quarantine_path,
        recommended_action=recommended_action(severity, request.remediation_mode),
    )


def scan(request: AVScanRequest) -> AVScanResponse:
    started = now()
    findings: List[AVFileFinding] = []
    errors: List[str] = []
    skipped = 0
    try:
        targets, initial_skipped = iter_targets(request)
        skipped += initial_skipped
    except Exception as exc:
        raise exc
    max_size = request.max_file_size_mb * 1024 * 1024
    scanned = 0
    for target in targets:
        try:
            if target.stat().st_size > max_size:
                skipped += 1
                continue
            scanned += 1
            finding = scan_file(target, request)
            if finding.severity != AVSeverity.clean or finding.rule_matches or finding.threat_feed_matches or finding.yara_matches:
                findings.append(finding)
        except Exception as exc:
            errors.append(f"{target}: {exc}")
    highest_severity = AVSeverity.clean
    for finding in findings:
        if SEVERITY_SCORE[finding.severity] > SEVERITY_SCORE[highest_severity]:
            highest_severity = finding.severity
    completed = now()
    status = "clean" if not findings else "findings_detected"
    response = AVScanResponse(
        status=status,
        target=request.path,
        scanned_files=scanned,
        skipped_files=skipped,
        finding_count=len(findings),
        highest_severity=highest_severity,
        remediation_mode=request.remediation_mode,
        findings=findings,
        started_at=started,
        completed_at=completed,
        errors=errors,
    )
    output_path = RESULTS_DIR / f"native-av-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    output_path.write_text(json.dumps(response.model_dump(), indent=2, default=str), encoding="utf-8")
    response.stored_result = str(output_path)
    return response


def engine_status() -> dict:
    status = {
        "status": "available",
        "engine": "sentinel_native_av",
        "mode": "native",
        "yara_available": yara_available(),
        "result_path": str(RESULTS_DIR),
        "default_remediation": "scan_only",
        "message": "Sentinel-native AV engine is available. Quarantine is disabled unless explicitly requested.",
    }
    status.update(rule_pack_status())
    return status
