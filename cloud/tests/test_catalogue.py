"""The community catalogue: checksummed app and script files, loaded into the software catalogue and script library."""

import shutil

from fenrir_cloud import catalogue, db as database
from fenrir_cloud.models import Script, SoftwarePackage
from fenrir_cloud.rmm_library import SCRIPTS


def test_the_shipped_catalogue_is_complete_and_valid():
    apps, scripts = catalogue.load_apps(), catalogue.load_scripts()
    assert len(apps) >= 100 and len(scripts) + len(SCRIPTS) >= 100
    assert len({a["winget"] for a in apps}) == len(apps)  # no app listed twice
    assert not {s["name"] for s in scripts} & {s["name"] for s in SCRIPTS}  # no clash with the built-ins
    chrome = next(a for a in apps if a["key"] == "google-chrome")
    assert chrome["winget"] == "Google.Chrome" and chrome["brew"] == "google-chrome"
    assert catalogue.match("Google Chrome")["key"] == "google-chrome" and catalogue.match("Totally Unknown App") is None
    sizes = next(s for s in scripts if s["name"] == "Largest folders on C:")
    assert sizes["language"] == "powershell" and sizes["parameters"][0]["name"] == "Path" and sizes["timeout_seconds"] == 1800
    assert any(s["platforms"] == ["macos"] for s in scripts) and any("linux" in s["platforms"] for s in scripts)


def test_startup_seeds_the_catalogue_once(client, admin):
    packages = client.get("/api/console/rmm/software", headers=admin).json()
    assert any(p["identifier"] == "Notepad++.Notepad++" and p["installer"] == "winget" for p in packages)
    assert any(p["identifier"] == "visual-studio-code" and p["installer"] == "brew" and p["platform"] == "macos" for p in packages)
    scripts = client.get("/api/console/rmm/scripts", headers=admin).json()
    assert any(s["name"] == "Windows 11 readiness" for s in scripts) and any(s["name"] == "FileVault status" for s in scripts)
    with database.session_factory()() as session:
        before = (session.query(SoftwarePackage).count(), session.query(Script).count())
        assert catalogue.seed(session) == {"apps": 0, "scripts": 0}
        session.commit()
        assert (session.query(SoftwarePackage).count(), session.query(Script).count()) == before


def test_files_not_in_the_manifest_or_changed_are_ignored(tmp_path):
    root = tmp_path / "catalogue"
    shutil.copytree(catalogue.ROOT, root)
    (root / "apps" / "google-chrome.yml").write_text("name: Evil\nwindows:\n  winget: Evil.Payload\n")  # edited, not reviewed
    (root / "scripts" / "unix" / "sneaky.sh").write_text("#!/bin/sh\n# name: Sneaky\n# platforms: linux\nrm -rf /\n")  # not listed
    apps, scripts = catalogue.load_apps(root), catalogue.load_scripts(root)
    assert not any(a["winget"] == "Evil.Payload" for a in apps) and not any(a["key"] == "google-chrome" for a in apps)
    assert not any(s["name"] == "Sneaky" for s in scripts)


def test_bad_headers_are_rejected(tmp_path):
    bad = tmp_path / "x.ps1"
    for text in ("# description: no name\nWrite-Output 1\n", "# name: X\n# platforms: linux\nWrite-Output 1\n",
                 "# name: X\n# platforms: windows\n# param: 1bad | L | string | | optional\n", "# name: X\n# platforms: windows\n# timeout: 99999\n"):
        bad.write_text(text)
        try:
            catalogue._parse_script(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted: {text!r}")


def test_a_windows_checkout_with_crlf_line_endings_still_loads(tmp_path):
    root = tmp_path / "catalogue"
    shutil.copytree(catalogue.ROOT, root)
    for path in list(root.glob("scripts/**/*.*")) + list(root.glob("apps/*.yml")):
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert len(catalogue.load_apps(root)) == len(catalogue.load_apps()) and len(catalogue.load_scripts(root)) == len(catalogue.load_scripts())


def test_catalogue_scripts_count_as_shipped_until_edited(client, admin):
    rows = client.get("/api/console/rmm/scripts", headers=admin).json()
    community = [s for s in rows if s["builtin"] and s.get("updatedBy") == "catalogue"]
    assert community and all(s["review"]["status"] == "shipped" for s in community)
