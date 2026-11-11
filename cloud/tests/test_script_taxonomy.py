"""Script library categories: Operating system / Area / Kind, previewed and applied without touching reviews."""

from fenrir_cloud.script_taxonomy import classify


def cat(name, platforms, description="", body=""):
    return classify(name, description, body, platforms)["category"]


def test_operating_system_area_and_kind():
    assert cat("Check: Linux Ransomware Canary", ["linux", "macos"]) == "Linux / Security / Check"
    assert cat("Mac - Isolate Device (Ransomware Containment)", ["linux", "macos"]) == "macOS / Incident response / Response"
    assert cat("Action: Remove WaveBrowser.exe Vulnerability", ["windows"]) == "Windows / Security / Fix"
    assert cat("Action: Update Windows Store Apps", ["windows"]) == "Windows / Patching and updates / Action"
    assert cat("Flush DNS and renew IP", ["windows"]) == "Windows / Networking / Fix"
    assert cat("Listening ports (Linux/macOS)", ["linux", "macos"], "Programs listening for network connections.") \
        == "Linux & macOS / Networking / Check"
    assert cat("Turn on Windows Firewall", ["windows"], "Enables Windows Firewall on all profiles (changes the system).") \
        == "Windows / Security / Action"
    assert cat("Bitlocker setup", ["windows"]) == "Windows / Encryption / Action"
    assert cat("Lismat macos filevault key extract", ["macos"]) == "macOS / Encryption / Check"


def test_preview_and_apply_change_only_the_category(client, admin):
    created = client.post("/api/console/rmm/scripts", headers=admin,
                          json={"name": "Linux - Block DNS", "category": "Misc", "language": "bash", "platforms": ["linux"],
                                "body": "#!/bin/sh\niptables -A OUTPUT -p udp --dport 53 -j DROP"}).json()
    builtin = next(s for s in client.get("/api/console/rmm/scripts", headers=admin).json()
                   if s["builtin"] and s["updatedBy"] in ("system", "catalogue"))
    preview = client.get("/api/console/rmm/script-categories", headers=admin).json()
    mine = next(c for c in preview["changes"] if c["id"] == created["id"])
    assert mine["proposed"] == "Linux / Networking / Action" and mine["current"] == "Misc"
    assert client.get(f"/api/console/rmm/scripts/{created['id']}", headers=admin).json()["category"] == "Misc"  # preview changed nothing

    applied = client.post("/api/console/rmm/script-categories", headers=admin,
                          json={"overrides": {builtin["id"]: "Windows / Testing / Check"}}).json()
    assert applied["changed"] >= 2
    after = {s["id"]: s for s in client.get("/api/console/rmm/scripts", headers=admin).json()}
    assert after[created["id"]]["category"] == "Linux / Networking / Action"
    assert after[builtin["id"]]["category"] == "Windows / Testing / Check"
    # Re-filing is not an edit: built-ins keep their shipped status and version.
    assert after[builtin["id"]]["review"]["status"] == builtin["review"]["status"]
    assert after[builtin["id"]]["version"] == builtin["version"] and after[builtin["id"]]["updatedBy"] == builtin["updatedBy"]


def test_new_scripts_without_a_category_are_filed(client, admin):
    created = client.post("/api/console/rmm/scripts", headers=admin,
                          json={"name": "Restart the print spooler", "language": "powershell", "body": "Restart-Service Spooler"}).json()
    assert created["category"] == "Windows / Printing / Action"
