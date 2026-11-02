import os

os.environ.setdefault("SENTINEL_SECRET_KEY", "test-only-secret-key-for-smoke-tests")

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_endpoint_sample_baseline():
    response = client.get("/api/endpoint/sample")
    assert response.status_code == 200
    data = response.json()
    assert "endpoint" in data
    assert "assessment" in data
    assert "risk_score" in data["assessment"]
    assert isinstance(data["assessment"].get("findings"), list)


def test_ioc_validation_pipeline_extracts_iocs():
    response = client.post("/api/ioc/validate", json={"input": "hxxps://evil[.]example/test 8.8.8.8 CVE-2024-12345"})
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 2
    assert data["valid_count"] >= 2


def test_endpoint_ioc_scanner_runs_safely():
    response = client.post(
        "/api/ioc-scanner/scan",
        json={
            "indicators": "8.8.8.8\nexample.com\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "scan_paths": [],
            "include_files": False,
            "include_processes": True,
            "include_network": True,
            "include_registry_autoruns": False,
            "include_dns_cache": False,
            "include_recent_logs": False,
            "max_files": 10,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert "summary" in data
    assert "findings" in data
    assert "recommended_actions" in data


def test_network_snapshot_runs():
    response = client.post("/api/network/snapshot", json={"include_listening": True, "include_loopback": False, "include_private_remote": True})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert "connections" in data
    assert "summary" in data


def test_persistence_scan_runs():
    response = client.post(
        "/api/persistence/scan",
        json={
            "include_services": False,
            "include_startup": False,
            "include_scheduled_tasks": False,
            "include_powershell_profiles": True,
            "include_browser_extensions": False,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert "summary" in data
    assert "findings" in data


def test_phishing_analyser_runs():
    raw = """From: Security Team <security@example.com>\nReply-To: attacker@evil.example\nReturn-Path: <bounce@evil.example>\nSubject: Urgent password verify\nAuthentication-Results: mx.example; spf=fail smtp.mailfrom=evil.example; dkim=fail; dmarc=fail\n\nPlease verify your password at http://192.0.2.10/login\n"""
    response = client.post("/api/phish/analyse", json={"raw_email": raw, "source_name": "smoke.eml"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "complete"
    assert data["summary"]["finding_count"] >= 1
    assert isinstance(data.get("urls"), list)


def test_case_lifecycle_minimal():
    create_response = client.post(
        "/api/cases/",
        json={"title": "Smoke test case", "severity": "medium", "status": "open", "summary": "Created by smoke test."},
    )
    assert create_response.status_code == 200
    case = create_response.json()["case"]
    case_id = case["case_id"]
    update_response = client.patch(f"/api/cases/{case_id}", json={"note": "Smoke test note", "action": {"action": "Review smoke test output"}})
    assert update_response.status_code == 200
    report_response = client.post(f"/api/cases/{case_id}/report")
    assert report_response.status_code == 200
    get_response = client.get(f"/api/cases/{case_id}")
    assert get_response.status_code == 200
    assert get_response.json()["case"]["case_id"] == case_id


def test_cve_manual_scan_runs():
    response = client.post("/api/cve/scan", json={"vendor": "Apache", "product": "Log4j", "version": "2.14.1", "include_non_exact": True})
    assert response.status_code == 200
    data = response.json()
    assert "vulnerabilities" in data
    assert data["count"] >= 1
