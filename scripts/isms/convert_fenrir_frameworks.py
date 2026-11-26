"""Converts Fenrir's Governance frameworks (cloud/fenrir_cloud/grc_library) into ISMS content packs.

    python3 scripts/isms/convert_fenrir_frameworks.py

Writes cloud/fenrir_cloud/isms/packs/<pack>/ for the ten frameworks the standalone ISMS had no pack for. Only
identifiers and Fenrir's own short titles are taken: Fenrir's requirement summaries are not copied (decision R1).
Mappings to common controls come from Fenrir's crosswalk (FC control -> requirement) through the FC -> common control
map, plus the hand mappings below for requirements the crosswalk does not cover. Programme steps (scope, certification
and assurance cycle) are mandatory: they always apply and are evidenced by the ISMS process, not a control, like the
ISO 27001 clauses. Review the output and run the content tests before committing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2] / "cloud"
sys.path.insert(0, str(ROOT))
from fenrir_cloud.isms.fenrir_map import FENRIR_CONTROL_MAP  # noqa: E402

LIBRARY = ROOT / "fenrir_cloud" / "grc_library"
PACKS = ROOT / "fenrir_cloud" / "isms" / "packs"

EU = ("(c) European Union, https://eur-lex.europa.eu. Reuse is authorised under Commission Decision 2011/833/EU. "
      "Identifiers are the official ones; short titles are our own.")
FRAMEWORKS = {
    # Fenrir key: (pack id, framework slug, licence, certifiable, attribution)
    "cyber-essentials-plus": ("cyber-essentials-plus", "cyber-essentials-plus", "crown-copyright-pending", True,
                              "Cyber Essentials Plus, NCSC and IASME. Identifiers and short titles only."),
    "cis-v8-ig1": ("cis-controls-v8-ig1", "cis-controls", "id-and-title", False,
                   "CIS Critical Security Controls v8.1, (c) Center for Internet Security. Safeguard numbers and short "
                   "titles only."),
    "def-stan-05-138": ("def-stan-05-138", "def-stan-05-138", "crown-copyright-pending", False,
                        "Def Stan 05-138, UK Ministry of Defence. Identifiers and short titles only."),
    "dora": ("dora-2022", "dora", "open", False, "Regulation (EU) 2022/2554 (DORA). " + EU),
    "eu-gdpr": ("eu-gdpr-2016", "eu-gdpr", "open", False, "Regulation (EU) 2016/679 (GDPR). " + EU),
    "govassure": ("govassure", "govassure", "crown-copyright-pending", False,
                  "GovAssure, UK Government Security Group. Identifiers and short titles only."),
    "govs-007": ("govs-007", "govs-007", "crown-copyright-pending", False,
                 "Government Functional Standard GovS 007: Security. Identifiers and short titles only."),
    "nis2": ("nis2-2022", "nis2", "open", False, "Directive (EU) 2022/2555 (NIS 2). " + EU),
    "pci-dss": ("pci-dss-4", "pci-dss", "id-and-title", True,
                "PCI DSS v4.0.1, (c) PCI Security Standards Council. Requirement numbers and short titles only."),
    "soc2": ("soc2-2017", "soc2", "id-and-title", True,
             "SOC 2 Trust Services Criteria, (c) AICPA. Criteria identifiers and short titles only."),
}

# Requirements the crosswalk does not cover: common controls, or "mandatory" for programme steps.
HAND: dict[str, dict[str, tuple[str, ...] | str]] = {
    "cyber-essentials-plus": {"CEP-SCOPE": "mandatory", "CEP-EXTERNAL": ("CC-VUL-01", "CC-NET-01"),
                              "CEP-INTERNAL": ("CC-VUL-01", "CC-CFG-01"), "CEP-ACCESS": ("CC-ACC-01",),
                              "CEP-RETEST": ("CC-VUL-01",), "CEP-DECISION": "mandatory"},
    "cis-v8-ig1": {"3.1": ("CC-CLS-01", "CC-GOV-08"), "3.2": ("CC-AST-01",), "3.3": ("CC-ACC-01",),
                   "3.4": ("CC-GOV-08",), "3.5": ("CC-MED-01",), "4.6": ("CC-CFG-01",), "9.1": ("CC-VUL-01",),
                   "12.1": ("CC-NET-01", "CC-VUL-01")},
    "def-stan-05-138": {"CSM-SCOPE": "mandatory", "CSM-PROFILE": "mandatory", "CSM-BASELINE": "mandatory",
                        "CSM-SAQ": "mandatory", "CSM-DCC": "mandatory", "CSM-CIP": "mandatory",
                        "CSM-INCIDENT": ("CC-INC-01",), "CSM-REVIEW": ("CC-GOV-10",)},
    "dora": {"DORA-SCOPE": "mandatory", "DORA-GOV": ("CC-GOV-02",), "DORA-RISK": "mandatory",
             "DORA-TEST": ("CC-BCM-01", "CC-VUL-01"), "DORA-TLPT": "mandatory", "DORA-REVIEW": ("CC-INC-02",)},
    "eu-gdpr": {"GDPR-SCOPE": "mandatory", "GDPR-ROLES": ("CC-GOV-09", "CC-SUP-01"), "GDPR-LAWFUL": ("CC-GOV-09",),
                "GDPR-RIGHTS": ("CC-GOV-09",), "GDPR-DPIA": ("CC-GOV-09",),
                "GDPR-SECURITY": ("CC-GOV-09", "CC-CRY-01"), "GDPR-TRANSFERS": ("CC-TRF-01", "CC-GOV-09"),
                "GDPR-RETENTION": ("CC-GOV-08", "CC-MED-01")},
    "govassure": {"GA-1": "mandatory", "GA-2": "mandatory", "GA-3": "mandatory", "GA-4": ("CC-GOV-10",),
                  "GA-5": "mandatory", "GA-REVIEW": "mandatory"},
    "govs-007": {"G007-RISK": "mandatory", "G007-PEOPLE": ("CC-HR-01", "CC-AWR-01"),
                 "G007-PHYSICAL": ("CC-PHY-01", "CC-AST-01"), "G007-TECH": ("CC-CFG-01", "CC-VUL-01"),
                 "G007-REVIEW": ("CC-GOV-10",)},
    "nis2": {"NIS2-SCOPE": "mandatory", "NIS2-20": ("CC-GOV-02", "CC-AWR-01"), "NIS2-21f": ("CC-GOV-11",)},
    "pci-dss": {"PCI-4": ("CC-CRY-01", "CC-TRF-01"), "PCI-9": ("CC-PHY-01",)},
    "soc2": {"CC1.1": ("CC-AUP-01", "CC-HR-02"), "CC1.2": ("CC-GOV-10",), "CC1.3": ("CC-GOV-02",),
             "CC1.5": ("CC-HR-02",), "CC2.1": ("CC-LOG-01",), "CC2.2": ("CC-GOV-01",), "CC2.3": ("CC-GOV-04",),
             "CC3.1": "mandatory", "CC3.2": "mandatory", "CC3.3": "mandatory", "CC3.4": ("CC-CHG-01",),
             "CC4.1": ("CC-GOV-11", "CC-GOV-10"), "CC4.2": ("CC-INC-02",), "CC5.1": "mandatory",
             "CC5.2": ("CC-CFG-01", "CC-CHG-01"), "CC6.1": ("CC-ACC-01", "CC-IAM-01"), "CC6.4": ("CC-PHY-01",),
             "CC6.5": ("CC-MED-01",), "CC6.7": ("CC-TRF-01", "CC-CRY-01")},
}


def _short(title: str) -> str:
    title = " ".join(str(title).split())
    if len(title) < 80:
        return title
    cut = title[:76].rsplit(" ", 1)[0]
    return cut.rstrip(",;:") + "..."


def _kebab(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower()).strip("-")


def _requirement(raw) -> tuple[str, str]:
    if isinstance(raw, (list, tuple)):
        return str(raw[0]).strip(), str(raw[1]).strip()
    return str(raw["id"]).strip(), str(raw.get("title") or raw["id"]).strip()


def _dump(path: Path, header: str, data) -> None:
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=False, width=120)
    path.write_text(f"# {header}\n{body}", encoding="utf-8")


def convert() -> None:
    crosswalk = yaml.safe_load((LIBRARY / "crosswalk.yml").read_text())["controls"]
    for key, (pack_id, slug, licence, certifiable, attribution) in FRAMEWORKS.items():
        src = yaml.safe_load((LIBRARY / f"{key}.yml").read_text())
        out = PACKS / pack_id
        out.mkdir(parents=True, exist_ok=True)
        groups, requirements, mappings = [], [], []
        hand = HAND.get(key, {})
        for i, section in enumerate(src["sections"], start=1):
            gref = _kebab(str(section["id"]))
            groups.append({"ref": gref, "title": _short(section["title"]), "sort": i, "licence": licence})
            for raw in section["requirements"]:
                ref, title = _requirement(raw)
                requirements.append({"ref": ref, "group": gref, "short_title": _short(title),
                                     "mandatory": hand.get(ref) == "mandatory", "licence": licence})
        refs = {r["ref"] for r in requirements}
        seen = set()
        for fc in crosswalk:
            for ref in fc["maps"].get(key, []):
                for cc in FENRIR_CONTROL_MAP.get(fc["id"], ()):
                    if ref in refs and (ref, cc) not in seen and hand.get(ref) != "mandatory":
                        seen.add((ref, cc))
                        mappings.append({"requirement": ref, "control": cc, "strength": "satisfies",
                                         "rationale": f"Fenrir's crosswalk maps {fc['id']} ({fc['title']}) here.",
                                         "licence": "original"})
        for ref, target in hand.items():
            if target == "mandatory":
                continue
            for cc in target:
                if (ref, cc) not in seen:
                    seen.add((ref, cc))
                    mappings.append({"requirement": ref, "control": cc, "strength": "satisfies",
                                     "rationale": "Mapped by hand when the pack was converted from Fenrir's library.",
                                     "licence": "original"})
        meta = {"id": pack_id, "kind": "framework", "framework": slug, "name": src["name"],
                "version": str(src.get("version") or "1"), "pack_version": "1.0.0", "certifiable": certifiable,
                "licence": licence, "attribution": attribution, "depends_on": ["common-controls"]}
        note = f"Converted from Fenrir's grc_library/{key}.yml by scripts/isms/convert_fenrir_frameworks.py."
        _dump(out / "pack.yaml", note, meta)
        _dump(out / "groups.yaml", note, groups)
        _dump(out / "requirements.yaml", note + " Identifiers and short titles only.", requirements)
        _dump(out / "mappings.yaml", note, sorted(mappings, key=lambda m: (m["requirement"], m["control"])))
        print(f"{pack_id}: {len(requirements)} requirements, {len(mappings)} mappings")


if __name__ == "__main__":
    convert()
