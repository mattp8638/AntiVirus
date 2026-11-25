"""Security questionnaires (GRC-15): library answers are suggested, never asserted; stale and unverified answers are
flagged; every answer is reviewed by a person before the questionnaire completes; exports are hashed."""

from datetime import timedelta

from fenrir_cloud.db import session_factory
from fenrir_cloud.models import GrcAnswer, utcnow


def test_questionnaire_from_library_with_review_and_flags(client, admin, tenant):
    tid = tenant["id"]
    ev = client.post("/api/console/grc/evidence", headers=admin, json={"tenantId": tid, "title": "Backup restore test report",
                                                                       "kind": "link", "url": "https://example.com/report"})
    assert ev.status_code == 200, ev.text
    a = client.post("/api/console/grc/answers", headers=admin, json={
        "tenantId": tid, "question": "Do you back up customer data and test restores?",
        "answer": "Yes: nightly immutable backups; restores are tested quarterly.", "evidenceIds": [ev.json()["id"]]}).json()
    plain = client.post("/api/console/grc/answers", headers=admin, json={
        "tenantId": tid, "question": "Is multi-factor authentication enforced for administrators?", "answer": "Yes."}).json()
    for x in (a, plain):
        client.patch(f"/api/console/grc/answers/{x['id']}", headers=admin, json={"action": "approve"})

    csv_text = "id,section,question\n1.1,Backup,Do you back up customer data and regularly test restoring it?\n2.1,Access,Is MFA enforced for all administrator accounts?\n3.1,HR,Do staff receive security awareness training?\n"
    r = client.post("/api/console/grc/questionnaires", headers=admin, json={"tenantId": tid, "title": "Globex vendor review",
                                                                           "counterparty": "Globex", "questions": csv_text})
    assert r.status_code == 200, r.text
    x = r.json()
    q1, q2, q3 = x["questions"]
    assert (q1["ref"], q1["section"], q1["state"]) == ("1.1", "Backup", "unanswered")
    base = f"/api/console/grc/questionnaires/{x['id']}/questions"
    sug = client.get(f"{base}/{q1['id']}/suggestions", headers=admin).json()
    assert sug and sug[0]["answerId"] == a["id"] and sug[0]["unverified"] is False
    assert client.get(f"{base}/{q3['id']}/suggestions", headers=admin).json() == [], "no weak matches"

    # Nothing is answered until a person picks the suggestion; then it still needs review.
    assert client.get(f"/api/console/grc/questionnaires/{x['id']}", headers=admin).json()["counts"] == {"unanswered": 3}
    r1 = client.patch(f"{base}/{q1['id']}", headers=admin, json={"fromAnswer": a["id"], "assignee": "ops@acme.test"}).json()
    assert r1["state"] == "drafted" and r1["flags"] == []
    r2 = client.patch(f"{base}/{q2['id']}", headers=admin, json={"fromAnswer": plain["id"]}).json()
    assert any(f.startswith("unverified") for f in r2["flags"]), "no evidence behind the library answer"
    r3 = client.patch(f"{base}/{q3['id']}", headers=admin, json={"answer": "Yes, annually."}).json()
    assert any("no evidence" in f for f in r3["flags"])
    assert "not reviewed" in client.post(f"/api/console/grc/questionnaires/{x['id']}/complete", headers=admin).text

    # The backup answer goes stale when its review period passes.
    with session_factory()() as db:
        db.get(GrcAnswer, a["id"]).approved_at = utcnow() - timedelta(days=400)
        db.commit()
    full = client.get(f"/api/console/grc/questionnaires/{x['id']}", headers=admin).json()
    assert any(f.startswith("stale") for f in full["questions"][0]["flags"])

    for q in (q1, q2, q3):
        assert client.patch(f"{base}/{q['id']}", headers=admin, json={"review": True}).json()["state"] == "reviewed"
    done = client.post(f"/api/console/grc/questionnaires/{x['id']}/complete", headers=admin).json()
    assert done["status"] == "completed"
    exp = client.get(f"/api/console/grc/questionnaires/{x['id']}/export.csv", headers=admin)
    assert "Yes, annually." in exp.text and "stale" in exp.text and len(exp.headers["X-Content-SHA256"]) == 64
    lib = client.post(f"{base}/{q3['id']}/to-library", headers=admin).json()
    assert lib["status"] == "draft" and lib["stale"] is True
