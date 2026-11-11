"""scripts/migrate/level_scripts.py: Level.io scripts mapped onto Fenrir's library."""

import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().parents[2] / "scripts" / "migrate" / "level_scripts.py"
_spec = importlib.util.spec_from_file_location("level_scripts", _path)
lvl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lvl)


def test_language_platform_and_category_are_worked_out():
    ps = {"name": "Clear temp files", "content": "Remove-Item \"$env:TEMP\\*\" -Recurse"}
    sh = {"name": "Disk usage", "content": "#!/bin/bash\ndf -h /", "os": "linux"}
    assert lvl.language_of(ps, ps["content"]) == "powershell" and lvl.platforms_of(ps, "powershell") == ["windows"]
    assert lvl.language_of(sh, sh["content"]) == "bash" and lvl.platforms_of(sh, "bash") == ["linux"]
    assert lvl.category_of(ps, ps["content"]) == ("Maintenance", "auto")
    assert lvl.category_of({"folder": {"name": "Onboarding"}}, "") == ("Onboarding", "level")
    assert lvl.category_of({"name": "x", "tags": ["Security"]}, "") == ("Security", "level tag")


def test_variables_become_parameters_and_custom_fields():
    body = "Restart-Service {{service_name}}\n$o = '{{cf_owner}}'"
    params, notes = lvl.parameters_of(body, {"variables": [{"name": "service_name", "label": "Service", "required": True}]})
    assert [p["name"] for p in params] == ["service_name"] and params[0]["required"] and params[0]["label"] == "Service"
    assert any("custom field 'owner'" in n for n in notes)
    assert lvl.rewrite_variables(body, "powershell") == 'Restart-Service $service_name\n$o = "$env:FENRIR_CF_OWNER"'
    assert lvl.rewrite_variables("X='{{path}}'; echo {{cf_site}}", "bash") == 'X="${path}"; echo ${FENRIR_CF_SITE}'
    assert lvl.quoting_notes("Write-Host 'svc {{name}} x'", "powershell")


def test_list_shapes_are_accepted():
    assert len(lvl.as_list({"data": [{"id": 1}, {"id": 2}]})) == 2
    assert len(lvl.as_list([{"id": 1}])) == 1 and lvl.as_list("nope") == []


def test_nested_and_json_lines_outputs_are_found():
    assert len(lvl.as_list({"data": {"scripts": {"nodes": [{"id": "1", "name": "A"}, {"id": "2", "name": "B"}]}}})) == 2
    assert len(lvl.as_list({"edges": [{"node": {"id": "1", "name": "A"}}], "pageInfo": {}})) == 1
    assert len(lvl.as_list(lvl.parse_json('{"id": "1", "name": "A"}\n{"id": "2", "name": "B"}\n'))) == 2
