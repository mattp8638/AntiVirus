"""AI helpdesk triage: local rules, Claude through the outbox, redaction, fallback and apply rules."""

import json
from types import SimpleNamespace

import pytest

from conftest import enroll
from fenrir_cloud import ai_helpdesk, events
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import KbArticle, Ticket


class FakeClaude:
    """Stands in for anthropic.Anthropic(): records requests and returns a canned structured answer."""

    def __init__(self, answer=None, stop_reason="end_turn", error=None):
        self.requests, self.answer, self.stop_reason, self.error = [], answer, stop_reason, error
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(stop_reason=self.stop_reason,
                               content=[SimpleNamespace(type="text", text=json.dumps(self.answer or {}))])


def configure(client, admin, mode, engine="local"):
    response = client.put("/api/console/psa/ai-triage", json={"mode": mode, "engine": engine}, headers=admin)
    assert response.status_code == 200, response.text


def new_ticket(client, admin, tenant, subject, description="", **extra):
    response = client.post("/api/console/tickets", json={"accountTenantId": tenant["id"], "subject": subject,
                                                             "description": description, **extra}, headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def process_events():
    with session_factory()() as db:
        events.process(db)
        db.commit()


def test_local_triage_from_the_outbox_suggests_without_changing_the_ticket(client, admin, tenant):
    with session_factory()() as db:
        db.add(KbArticle(tenant_id=tenant["id"], title="Fix a stuck print queue", body="Restart the print spooler service"))
        db.commit()
    configure(client, admin, "suggest")
    ticket = new_ticket(client, admin, tenant, "Printer queue stuck", "The office printer queue is stuck, nothing prints")
    process_events()
    with session_factory()() as db:
        row = db.get(Ticket, ticket["id"])
        assert row.ai_triage["category"] == "printing" and row.ai_triage["engine"] == "local"
        assert row.ai_triage["suggestedKbIds"] and row.priority == "P3" and row.ai_triage["applied"] == []
        note = row.comments[-1]
        assert note["internal"] and "Fix a stuck print queue" in note["text"] and "Suggested reply (not sent)" in note["text"]


def test_apply_mode_only_raises_priority_and_skips_system_tickets(client, admin, tenant):
    configure(client, admin, "apply")
    urgent = new_ticket(client, admin, tenant, "Ransomware note on the file server", "All files encrypted, whole office down")
    calm = new_ticket(client, admin, tenant, "Question about Teams", "How do I share my screen? no rush", priority="P2")
    with session_factory()() as db:
        from fenrir_cloud import services

        system = services.open_ticket(db, tenant["id"], "Disk space low on SRV1", "monitor", "P3", "rmm").id
        db.commit()
    process_events()
    with session_factory()() as db:
        assert db.get(Ticket, urgent["id"]).priority == "P1" and db.get(Ticket, urgent["id"]).ai_triage["securityConcern"]
        kept = db.get(Ticket, calm["id"])
        assert kept.ai_triage["priority"] == "P4" and kept.priority == "P2"  # never lowered automatically
        assert db.get(Ticket, system).ai_triage is None  # monitor tickets are not triaged


def test_claude_engine_redacts_and_validates(client, admin, tenant, monkeypatch):
    device = enroll(client, admin, tenant, hostname="ACME-PC-7", serial="AI1")
    configure(client, admin, "suggest", engine="claude")
    fake = FakeClaude({"category": "account-access", "priority": "P2", "impact": "Medium", "urgency": "High",
                       "summary": "Locked out", "securityConcern": False, "suggestedKbIds": ["kb_does_not_exist"],
                       "suggestedPackage": "made-up", "suggestedReply": "We are on it.", "reasoning": "User locked out."})
    monkeypatch.setenv("FENRIR_ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("anthropic.Anthropic", lambda **kwargs: fake)
    ticket = new_ticket(client, admin, tenant, "Locked out of my account",
                        "My password is Hunter2!! and card 4111 1111 1111 1111, NI AB123456C", deviceId=device["deviceId"])
    process_events()
    request = fake.requests[0]
    sent = request["messages"][0]["content"]
    assert "Hunter2" not in sent and "4111" not in sent and "AB123456C" not in sent and "ACME-PC-7" in sent
    assert request["model"] == "claude-opus-5-5" and request["output_config"]["format"]["type"] == "json_schema"
    assert request["fallbacks"] == "default" and request["betas"] == ["server-side-fallback-2026-07-01"]
    with session_factory()() as db:
        result = db.get(Ticket, ticket["id"]).ai_triage
        assert result["engine"] == "claude" and result["category"] == "account-access"
        assert result["suggestedKbIds"] == [] and result["suggestedPackage"] == ""  # ids the model invented are dropped


@pytest.mark.parametrize("fake", [FakeClaude(error=RuntimeError("overloaded")), FakeClaude({}, stop_reason="refusal")])
def test_claude_failures_fall_back_to_local_rules(client, admin, tenant, monkeypatch, fake):
    configure(client, admin, "suggest", engine="claude")
    monkeypatch.setenv("FENRIR_ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("anthropic.Anthropic", lambda **kwargs: fake)
    ticket = new_ticket(client, admin, tenant, "Outlook keeps crashing")
    process_events()
    with session_factory()() as db:
        result = db.get(Ticket, ticket["id"]).ai_triage
        assert result["engine"] == "local (fallback)" and result["category"] == "email"


def test_triage_settings_and_on_demand(client, admin, tenant):
    assert client.put("/api/console/psa/ai-triage", json={"mode": "always"}, headers=admin).status_code == 422
    assert client.get("/api/console/psa/ai-triage", headers=admin).json()["mode"] == "off"
    ticket = new_ticket(client, admin, tenant, "VPN will not connect")
    process_events()
    with session_factory()() as db:
        assert db.get(Ticket, ticket["id"]).ai_triage is None  # off by default
    result = client.post(f"/api/console/tickets/{ticket['id']}/triage", headers=admin).json()
    assert result["category"] == "network" and result["mode"] == "suggest"


def test_redaction():
    text = ai_helpdesk.redact("password: Pa55word! token=abcdef card 5555 5555 5555 4444 NI QQ123456C key " + "A" * 40)
    assert "Pa55word" not in text and "abcdef" not in text and "4444" not in text and "AAAA" not in text
    assert "I reset my password yesterday" == ai_helpdesk.redact("I reset my password yesterday")
