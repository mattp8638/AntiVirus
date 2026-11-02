import os

os.environ.setdefault("SENTINEL_SECRET_KEY", "test-only-secret-key-for-smoke-tests")

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_phishing_analyser_explains_link_deception_and_html_forms():
    raw = """From: IT Support <support@example.com>
Reply-To: attacker@evil.test
Return-Path: <bounce@evil.test>
Subject: Urgent MFA password verify
Authentication-Results: mx.example; spf=fail smtp.mailfrom=evil.test; dkim=fail; dmarc=fail
Content-Type: text/html

<html>
  <body>
    <p style="display:none">hidden scanner text</p>
    <p>Your account is locked. Verify your password immediately.</p>
    <a href="http://evil.test/login.exe">https://example.com/login</a>
    <form action="http://evil.test/post"><input type="password" name="password"></form>
  </body>
</html>
"""

    response = client.post("/api/phish/analyse", json={"raw_email": raw, "source_name": "deception.eml"})

    assert response.status_code == 200
    data = response.json()
    titles = {finding["title"] for finding in data["findings"]}
    assert "Visible link text does not match destination" in titles
    assert "HTML credential collection form" in titles
    assert "Hidden or deceptive HTML content" in titles
    assert "External link does not match sender domain" in titles
    assert data["html_indicators"]["has_password_input"] is True
    assert data["link_mismatches"][0]["shown_host"] == "example.com"

    finding = next(item for item in data["findings"] if item["title"] == "Visible link text does not match destination")
    assert "In plain English" in finding["plain_english"]
    assert "actually points somewhere else" in finding["possible_intent"]
    assert finding["evidence_summary"]
    assert finding["analyst_next_step"] == finding["recommended_action"]


def test_phishing_upload_detects_double_extension_attachment():
    raw = (
        b"From: Billing <billing@example.com>\n"
        b"Subject: Invoice review\n"
        b"Content-Type: multipart/mixed; boundary=BOUNDARY\n\n"
        b"--BOUNDARY\n"
        b"Content-Type: text/plain\n\n"
        b"Please review the attached invoice.\n"
        b"--BOUNDARY\n"
        b"Content-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\n\n"
        b"MZ fake executable content\n"
        b"--BOUNDARY--\n"
    )

    response = client.post(
        "/api/phish/analyse-upload",
        files={"file": ("invoice.eml", raw, "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()
    titles = {finding["title"] for finding in data["findings"]}
    assert "Double-extension attachment" in titles
    assert data["attachments"][0]["double_extension"] is True
    assert data["attachments"][0]["extension"] == ".exe"
