"""Tenant isolation for ISMS data: tenant A can never list or load tenant B's rows.

Every ISMS table registered with ``@tenant_table`` needs a row factory in ``FACTORIES`` below; the first test fails
until it has one, and the isolation tests then run against it. The scoping helper itself is checked against an
existing tenant table (``grc_policies``).
"""

from dataclasses import dataclass
from datetime import date

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fenrir_cloud.isms.models import (IsmsApplicability, IsmsDocument, IsmsDocumentOverride, IsmsDocumentVersion, IsmsAudit, IsmsAuditCheck, IsmsAuditProgramme, IsmsChange, IsmsCorrectiveAction, IsmsEvidence, IsmsEvidenceLink, IsmsImport, IsmsMetricValue, IsmsNonconformity, IsmsObjective, IsmsLegacyAnswer, IsmsTask, IsmsApplicabilityOverride, IsmsAsset, IsmsContextIssue,
                                      IsmsEntity, IsmsInterestedParty, IsmsMembership, IsmsProfileAnswer, IsmsScope,
                                      IsmsRisk, IsmsRiskAcceptance, IsmsRiskControl, IsmsRiskMethod,
                                      IsmsRiskSnapshot, IsmsSite, IsmsTenantControl, IsmsTenantFramework)
from fenrir_cloud.isms.scope import TENANT_TABLES, get_scoped, require_same_tenant, scoped, tenant_table
from fenrir_cloud.models import Base, GrcPolicy

# Model -> function(tenant_id) returning an unsaved row for that tenant.
FACTORIES: dict[type, callable] = {
    IsmsMembership: lambda t: IsmsMembership(tenant_id=t, user_id=f"usr_{t}", role="staff"),
    IsmsScope: lambda t: IsmsScope(tenant_id=t, statement="All services"),
    IsmsEntity: lambda t: IsmsEntity(tenant_id=t, name="Acme Ltd"),
    IsmsSite: lambda t: IsmsSite(tenant_id=t, name="Head office"),
    IsmsContextIssue: lambda t: IsmsContextIssue(tenant_id=t, kind="external", description="New regulation"),
    IsmsInterestedParty: lambda t: IsmsInterestedParty(tenant_id=t, name="Customers"),
    IsmsAsset: lambda t: IsmsAsset(tenant_id=t, type="system", name="CRM"),
    IsmsTenantFramework: lambda t: IsmsTenantFramework(tenant_id=t, framework="iso27001", pack_id="iso27001-2022",
                                                       pack_version="1.1.0"),
    IsmsProfileAnswer: lambda t: IsmsProfileAnswer(tenant_id=t, question_ref="develops_software", value=True),
    IsmsApplicability: lambda t: IsmsApplicability(tenant_id=t, target_type="control", target_key="CC-BKP-01",
                                                   applicable=True, source="derived", reason="Needed."),
    IsmsApplicabilityOverride: lambda t: IsmsApplicabilityOverride(tenant_id=t, target_type="control",
                                                                   target_key="CC-BKP-01", applicable=False,
                                                                   justification="Not used."),
    IsmsTenantControl: lambda t: IsmsTenantControl(tenant_id=t, ref="CC-BKP-01", title="Backups", statement="x"),
    IsmsRiskMethod: lambda t: IsmsRiskMethod(tenant_id=t, likelihood_scale=[], impact_scale=[], levels=[], appetite=8,
                                             acceptance_criteria="x"),
    IsmsRisk: lambda t: IsmsRisk(tenant_id=t, ref="R-001", title="Ransomware"),
    IsmsRiskControl: lambda t: IsmsRiskControl(tenant_id=t, risk_id=f"irk_{t}", tenant_control_id=f"itc_{t}"),
    IsmsRiskAcceptance: lambda t: IsmsRiskAcceptance(tenant_id=t, risk_id=f"irk_{t}", accepted_by_user_id="u",
                                                     residual_score=4, rationale="Fine."),
    IsmsRiskSnapshot: lambda t: IsmsRiskSnapshot(tenant_id=t, payload={"risks": []}),
    IsmsEvidence: lambda t: IsmsEvidence(tenant_id=t, title="Backup report", kind="note", note="x"),
    IsmsEvidenceLink: lambda t: IsmsEvidenceLink(tenant_id=t, evidence_id=f"iev_{t}", tenant_control_id=f"itc_{t}"),
    IsmsTask: lambda t: IsmsTask(tenant_id=t, kind="manual", title="Board review", due_on=date(2027, 1, 31)),
    IsmsDocument: lambda t: IsmsDocument(tenant_id=t, doc_type="information-security-policy", title="Policy",
                                         number=f"X-POL-{t}"),
    IsmsDocumentVersion: lambda t: IsmsDocumentVersion(tenant_id=t, document_id=f"idc_{t}", version=1, template_ref="x",
                                                       context_hash="0" * 64, blocks=[], html=""),
    IsmsNonconformity: lambda t: IsmsNonconformity(tenant_id=t, ref="NC-001", title="Missing log review",
                                                   source="internal_audit", severity="minor", raised_on=date(2026, 11, 1)),
    IsmsCorrectiveAction: lambda t: IsmsCorrectiveAction(tenant_id=t, nonconformity_id=f"inc_{t}", description="Fix it",
                                                         due_on=date(2026, 12, 1)),
    IsmsObjective: lambda t: IsmsObjective(tenant_id=t, ref="OBJ-001", title="Patch fast", measure="Days to patch",
                                           direction="at_most", target=14),
    IsmsMetricValue: lambda t: IsmsMetricValue(tenant_id=t, objective_id=f"iob_{t}", measured_on=date(2026, 11, 1),
                                               value=10),
    IsmsChange: lambda t: IsmsChange(tenant_id=t, ref="CHG-001", title="New MDM", purpose="Manage phones"),
    IsmsAuditProgramme: lambda t: IsmsAuditProgramme(tenant_id=t, title="Programme", period_start=date(2027, 1, 1),
                                                     period_end=date(2027, 12, 31)),
    IsmsAudit: lambda t: IsmsAudit(tenant_id=t, programme_id=f"iap_{t}", ref="AUD-001", title="Audit",
                                   planned_start=date(2027, 3, 1), planned_end=date(2027, 3, 2)),
    IsmsAuditCheck: lambda t: IsmsAuditCheck(tenant_id=t, audit_id=f"iau_{t}", framework="iso27001",
                                             requirement_ref="9.2", requirement_title="Internal audit"),
    IsmsLegacyAnswer: lambda t: IsmsLegacyAnswer(tenant_id=t, framework="iso27001", source_framework="iso-27001",
                                                 source_ref="A.7.4", status="not_applicable"),
    IsmsImport: lambda t: IsmsImport(tenant_id=t, source_table="grc_policies", source_id=f"grcp_{t}",
                                     target_table="isms_documents"),
    IsmsDocumentOverride: lambda t: IsmsDocumentOverride(tenant_id=t, document_id=f"idc_{t}", block_ref="isp.purpose",
                                                         content="x"),
}


@dataclass
class FakePrincipal:
    tenant_ids: frozenset

    def check_tenant(self, tenant_id):
        if tenant_id not in self.tenant_ids:
            raise HTTPException(404, "Not found")


A = FakePrincipal(frozenset({"ten_a", "ten_a_site"}))  # a customer with one site below it


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    tables = [GrcPolicy.__table__, *(m.__table__ for m in FACTORIES)]
    Base.metadata.create_all(engine, tables=tables)
    with Session(engine) as session:
        yield session


def seed(db, model, make):
    rows = {t: make(t) for t in ("ten_a", "ten_a_site", "ten_b")}
    db.add_all(rows.values())
    db.commit()
    return rows


def test_every_isms_table_has_a_row_factory():
    assert set(TENANT_TABLES) == set(FACTORIES), "add a row factory for each new ISMS tenant table"


ALL = [(GrcPolicy, lambda t: GrcPolicy(tenant_id=t, title=f"Policy {t}")), *FACTORIES.items()]


@pytest.mark.parametrize("model,make", ALL, ids=lambda x: getattr(x, "__tablename__", ""))
def test_lists_show_only_visible_tenants(db, model, make):
    seed(db, model, make)
    rows = db.execute(scoped(model, A)).scalars().all()
    assert sorted(r.tenant_id for r in rows) == ["ten_a", "ten_a_site"]
    assert [r.tenant_id for r in db.execute(scoped(model, A, "ten_a_site")).scalars()] == ["ten_a_site"]
    count = db.execute(scoped(model, A, stmt=select(func.count()).select_from(model))).scalar_one()
    assert count == 2


@pytest.mark.parametrize("model,make", ALL, ids=lambda x: getattr(x, "__tablename__", ""))
def test_other_tenants_cannot_be_asked_for_or_loaded(db, model, make):
    rows = seed(db, model, make)
    with pytest.raises(HTTPException) as e:
        db.execute(scoped(model, A, "ten_b"))
    assert e.value.status_code == 404
    with pytest.raises(HTTPException) as e:
        get_scoped(db, model, rows["ten_b"].id, A)
    assert e.value.status_code == 404  # not 403: the id reveals nothing
    assert get_scoped(db, model, rows["ten_a"].id, A).tenant_id == "ten_a"
    with pytest.raises(HTTPException):
        get_scoped(db, model, "missing", A)


def test_linked_records_must_share_a_tenant():
    assert require_same_tenant([GrcPolicy(tenant_id="ten_a"), GrcPolicy(tenant_id="ten_a")]) == "ten_a"
    with pytest.raises(HTTPException) as e:
        require_same_tenant([GrcPolicy(tenant_id="ten_a"), GrcPolicy(tenant_id="ten_b")])
    assert e.value.status_code == 400


def test_registering_a_table_without_tenant_id_fails():
    class NoTenant:
        pass

    with pytest.raises(TypeError):
        tenant_table(NoTenant)
