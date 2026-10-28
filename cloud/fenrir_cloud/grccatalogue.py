"""UK and UK-relevant governance catalogue; source and applicability metadata."""
import re

CATALOGUE = {
    "cyber-essentials": {
        "name": "Cyber Essentials",
        "short": "Cyber Essentials",
        "version": "Requirements v3.3",
        "owner": "NCSC / IASME",
        "assessmentStyle": "Technical self-assessment",
        "targetScope": "UK organisations and public-sector suppliers; defined certification scope.",
        "jurisdiction": "UK",
        "sourceUrl": "https://www.ncsc.gov.uk/cyberessentials/resources",
        "aliases": [
            "Cyber Essentials"
        ]
    },
    "cyber-essentials-plus": {
        "name": "Cyber Essentials Plus",
        "short": "CE+",
        "version": "Current CE requirements and CE+ test specification",
        "owner": "NCSC / IASME",
        "assessmentStyle": "Independent technical verification",
        "targetScope": "UK organisations requiring independently verified Cyber Essentials controls.",
        "jurisdiction": "UK",
        "sourceUrl": "https://www.ncsc.gov.uk/cyberessentials/resources",
        "aliases": [
            "Cyber Essentials Plus",
            "CE+"
        ]
    },
    "def-stan-05-138": {
        "name": "Def Stan 05-138 / Cyber Security Model",
        "short": "MOD CSM",
        "version": "Issue 4 / CSMv4",
        "owner": "Ministry of Defence",
        "assessmentStyle": "Risk-profile assessment, supplier questionnaire and flow-down",
        "targetScope": "MOD suppliers and subcontractors subject to the applicable defence contract.",
        "jurisdiction": "UK",
        "sourceUrl": "https://www.gov.uk/guidance/cyber-security-model",
        "aliases": [
            "Def Stan 05-138",
            "CSM"
        ]
    },
    "ncsc-caf": {
        "name": "NCSC Cyber Assessment Framework",
        "short": "NCSC CAF",
        "version": "CAF 4.0",
        "owner": "NCSC",
        "assessmentStyle": "Outcome assessment using Indicators of Good Practice",
        "targetScope": "UK essential services, CNI, regulated sectors and applicable government profiles.",
        "jurisdiction": "UK",
        "sourceUrl": "https://www.ncsc.gov.uk/collection/cyber-assessment-framework",
        "aliases": [
            "NCSC CAF"
        ]
    },
    "govassure": {
        "name": "GovAssure",
        "short": "GovAssure",
        "version": "Current government CAF profiles",
        "owner": "Cabinet Office / Government Security Group",
        "assessmentStyle": "CAF-based self-assessment and independent assurance review",
        "targetScope": "Central government departments, arm's-length bodies and systems within GovAssure scope.",
        "jurisdiction": "UK",
        "sourceUrl": "https://www.security.gov.uk/policy-and-guidance/govassure/govassure-guidance/",
        "aliases": [
            "GovAssure"
        ]
    },
    "govs-007": {
        "name": "GovS 007: Security",
        "short": "GovS 007",
        "version": "2.0",
        "owner": "Cabinet Office",
        "assessmentStyle": "Government functional-standard assurance",
        "targetScope": "Security governance and operations across UK government organisations.",
        "jurisdiction": "UK",
        "sourceUrl": "https://www.gov.uk/government/publications/government-functional-standard-govs-007-security",
        "aliases": [
            "GovS 007"
        ]
    },
    "uk-gdpr": {
        "name": "UK GDPR / Data Protection Act 2018",
        "short": "UK GDPR / DPA",
        "version": "Current UK data-protection legislation",
        "owner": "ICO / UK Parliament",
        "assessmentStyle": "Data-protection accountability, DPIAs and compliance review",
        "targetScope": "UK organisations processing personal data; scope and exemptions require assessment.",
        "jurisdiction": "UK",
        "sourceUrl": "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/",
        "aliases": [
            "UK GDPR",
            "DPA 2018"
        ]
    },
    "eu-gdpr": {
        "name": "EU GDPR",
        "short": "EU GDPR",
        "version": "Regulation (EU) 2016/679",
        "owner": "EU / relevant supervisory authority",
        "assessmentStyle": "Data-protection accountability and cross-border review",
        "targetScope": "UK organisations within EU GDPR territorial scope, including relevant EU offerings or monitoring.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        "aliases": [
            "EU GDPR"
        ]
    },
    "iso-27001": {
        "name": "ISO/IEC 27001:2022",
        "short": "ISO 27001",
        "version": "2022",
        "owner": "ISO / IEC",
        "assessmentStyle": "ISMS implementation and independent certification audit",
        "targetScope": "UK and international enterprises, SaaS providers and supply chains.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://www.iso.org/standard/27001",
        "aliases": [
            "ISO 27001:2022",
            "ISO/IEC 27001:2022"
        ]
    },
    "nist-csf-2": {
        "name": "NIST CSF 2.0",
        "short": "NIST CSF",
        "version": "2.0",
        "owner": "NIST",
        "assessmentStyle": "Voluntary current/target profiles and maturity assessment",
        "targetScope": "UK organisations using an internationally recognised cyber-risk framework.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://www.nist.gov/cyberframework",
        "aliases": [
            "NIST CSF",
            "NIST Cybersecurity Framework 2.0"
        ]
    },
    "soc2": {
        "name": "SOC 2 (Type I and Type II)",
        "short": "SOC 2",
        "version": "Applicable Trust Services Criteria",
        "owner": "AICPA",
        "assessmentStyle": "Independent CPA examination of design and, for Type II, operating effectiveness",
        "targetScope": "UK SaaS, cloud and MSP organisations providing service-organisation assurance.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
        "aliases": [
            "SOC 2",
            "SOC2"
        ]
    },
    "pci-dss": {
        "name": "PCI DSS v4.0.1",
        "short": "PCI DSS",
        "version": "4.0.1",
        "owner": "PCI Security Standards Council",
        "assessmentStyle": "Applicable SAQ or QSA assessment",
        "targetScope": "UK organisations within payment-card data security scope; validation route depends on the payment programme.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://www.pcisecuritystandards.org/document_library/?category=pcidss",
        "aliases": [
            "PCI DSS",
            "PCI DSS v4.0"
        ]
    },
    "cis-v8-ig1": {
        "name": "CIS Controls v8.1 (IG1)",
        "short": "CIS IG1",
        "version": "8.1 / IG1",
        "owner": "Center for Internet Security",
        "assessmentStyle": "Prioritised technical safeguard implementation",
        "targetScope": "UK organisations building an essential cyber-hygiene implementation programme.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://www.cisecurity.org/controls/v8-1",
        "aliases": [
            "CIS Controls",
            "CIS Controls v8"
        ]
    },
    "nis2": {
        "name": "NIS 2 Directive",
        "short": "NIS 2",
        "version": "Directive (EU) 2022/2555",
        "owner": "EU / relevant national competent authority",
        "assessmentStyle": "Regulatory scope, risk-management and incident-reporting review",
        "targetScope": "UK organisations operating in an EU jurisdiction where the national implementing law brings them into scope.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
        "aliases": [
            "NIS 2",
            "NIS2"
        ]
    },
    "dora": {
        "name": "DORA",
        "short": "DORA",
        "version": "Regulation (EU) 2022/2554",
        "owner": "EU / relevant financial supervisory authority",
        "assessmentStyle": "ICT risk, resilience testing and third-party oversight",
        "targetScope": "UK entities with in-scope EU financial activities or relevant ICT supplier obligations.",
        "jurisdiction": "UK-targeted",
        "sourceUrl": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "aliases": [
            "DORA"
        ]
    }
}

RETIRED_KEYS = frozenset({"essential-eight", "acsc-essential-eight", "acsc"})


def retired_framework(key: str, name: str = "") -> bool:
    text = f"{key} {name}".lower().replace("_", "-")
    return key in RETIRED_KEYS or any(part in text for part in ("essential-eight", "essential eight", "australian cyber security")) or bool(re.search(r"\bacsc\b", text))


def framework_labels(key: str) -> set[str]:
    item = CATALOGUE.get(key, {})
    return {item.get("name", key), *item.get("aliases", [])}
