"""The risk workflow (ISO 27001 6.1.2, 6.1.3, 8.2, 8.3). Scores and levels come from the customer's risk method
through the pure functions in ``domain/risk.py``. Every change is audited."""

from __future__ import annotations

import re
from dataclasses import asdict
from datetime import date
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, utcnow
from .domain import risk as maths
from .domain._js import js_trim
from .models import (IsmsAsset, IsmsRisk, IsmsRiskAcceptance, IsmsRiskControl, IsmsRiskMethod, IsmsRiskSnapshot,
                     IsmsTenantControl)

TREATMENTS = ("modify", "retain", "avoid", "share")
STATUSES = ("identified", "assessed", "treatment_planned", "accepted", "closed")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


# Method -----------------------------------------------------------------------------------------------------

def _method_from_row(row: IsmsRiskMethod) -> maths.RiskMethod:
    return maths.RiskMethod([maths.ScalePoint(**p) for p in row.likelihood_scale],
                            [maths.ScalePoint(**p) for p in row.impact_scale],
                            [maths.LevelBand(**lv) for lv in row.levels], row.appetite, row.acceptance_criteria,
                            row.review_months)


def method_row(db: Session, tenant_id: str) -> IsmsRiskMethod | None:
    return db.execute(select(IsmsRiskMethod).where(IsmsRiskMethod.tenant_id == tenant_id)).scalar_one_or_none()


def get_method(db: Session, tenant_id: str) -> tuple[maths.RiskMethod, int]:
    """The customer's method and its version (0 while the default has not been saved)."""
    row = method_row(db, tenant_id)
    return (_method_from_row(row), row.version) if row else (maths.default_risk_method(), 0)


def method_dict(m: maths.RiskMethod, version: int) -> dict:
    return {"likelihoodScale": [asdict(p) for p in m.likelihood_scale],
            "impactScale": [asdict(p) for p in m.impact_scale], "levels": [asdict(lv) for lv in m.levels],
            "appetite": m.appetite, "acceptanceCriteria": m.acceptance_criteria, "reviewMonths": m.review_months,
            "maxScore": maths.max_score(m), "version": version, "saved": version > 0}


def parse_method(data: dict) -> maths.RiskMethod:
    try:
        return maths.RiskMethod(
            [maths.ScalePoint(int(p["value"]), str(p.get("label") or ""), str(p.get("description") or ""))
             for p in data["likelihoodScale"]],
            [maths.ScalePoint(int(p["value"]), str(p.get("label") or ""), str(p.get("description") or ""))
             for p in data["impactScale"]],
            [maths.LevelBand(int(lv["min"]), str(lv["level"]), str(lv["label"])) for lv in data["levels"]],
            data["appetite"], str(data.get("acceptanceCriteria") or ""), data.get("reviewMonths", 12))
    except (KeyError, TypeError, ValueError):
        raise _error("The risk method is incomplete.") from None


def save_method(db: Session, tenant_id: str, actor: str, m: maths.RiskMethod) -> int:
    """Saves the method; each change increments its version (the 6.1.2 documented information)."""
    issues = maths.validate_risk_method(m)
    if issues:
        raise _error(" ".join(i.message for i in issues))
    values = {"likelihood_scale": [asdict(p) for p in m.likelihood_scale],
              "impact_scale": [asdict(p) for p in m.impact_scale], "levels": [asdict(lv) for lv in m.levels],
              "appetite": int(m.appetite), "acceptance_criteria": js_trim(m.acceptance_criteria)[:4000],
              "review_months": int(m.review_months)}
    row = method_row(db, tenant_id)
    if row is None:
        row = IsmsRiskMethod(tenant_id=tenant_id, version=1, updated_by=actor, **values)
        db.add(row)
    elif any(getattr(row, k) != v for k, v in values.items()):
        for k, v in values.items():
            setattr(row, k, v)
        row.version += 1
        row.updated_at, row.updated_by = utcnow(), actor
    else:
        return row.version
    db.flush()
    audit.record(db, actor, "isms.risk_method_saved", f"version {row.version}", tenant_id, version=row.version)
    return row.version


# Risks ------------------------------------------------------------------------------------------------------

def _today():
    return utcnow().date()


def risk_views(db: Session, tenant_id: str, risk_id: str | None = None) -> list[dict]:
    m, _ = get_method(db, tenant_id)
    q = select(IsmsRisk).where(IsmsRisk.tenant_id == tenant_id)
    if risk_id:
        q = q.where(IsmsRisk.id == risk_id)
    risks = list(db.execute(q.order_by(IsmsRisk.ref)).scalars())
    ids = [r.id for r in risks]
    assets = {a.id: a.name for a in db.execute(select(IsmsAsset).where(IsmsAsset.tenant_id == tenant_id)).scalars()}
    links: dict[str, list[IsmsTenantControl]] = {}
    if ids:
        for rid, tc in db.execute(select(IsmsRiskControl.risk_id, IsmsTenantControl).join(
                IsmsTenantControl, IsmsTenantControl.id == IsmsRiskControl.tenant_control_id)
                .where(IsmsRiskControl.risk_id.in_(ids))).all():
            links.setdefault(rid, []).append(tc)
    acceptances: dict[str, IsmsRiskAcceptance] = {}
    if ids:
        for a in db.execute(select(IsmsRiskAcceptance).where(IsmsRiskAcceptance.risk_id.in_(ids))
                            .order_by(IsmsRiskAcceptance.accepted_at)).scalars():
            if a.expires_at is None or a.expires_at > _today():
                acceptances[a.risk_id] = a  # the latest current acceptance wins
    user_ids = {r.owner_user_id for r in risks} | {a.accepted_by_user_id for a in acceptances.values()}
    names = {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(user_ids - {None}))).scalars()}
    today = _today().isoformat()
    out = []
    for r in risks:
        inherent = maths.risk_score(m, r.inherent_likelihood, r.inherent_impact)
        residual = maths.risk_score(m, r.residual_likelihood, r.residual_impact)
        acc = acceptances.get(r.id)
        level = lambda s: (band.label if (band := maths.risk_level(m, s)) else None)  # noqa: E731
        next_review = r.next_review.isoformat() if r.next_review else None
        out.append({
            "id": r.id, "ref": r.ref, "title": r.title, "description": r.description, "threat": r.threat,
            "vulnerability": r.vulnerability, "assetIds": list(r.asset_ids or []),
            "assetNames": sorted(assets[a] for a in (r.asset_ids or []) if a in assets),
            "ownerId": r.owner_user_id, "ownerName": names.get(r.owner_user_id),
            "inherentLikelihood": r.inherent_likelihood, "inherentImpact": r.inherent_impact,
            "inherentScore": inherent, "inherentLevel": level(inherent), "treatment": r.treatment,
            "treatmentPlan": r.treatment_plan, "residualLikelihood": r.residual_likelihood,
            "residualImpact": r.residual_impact, "residualScore": residual, "residualLevel": level(residual),
            "withinAppetite": maths.within_appetite(m, residual if residual is not None else inherent),
            "status": r.status, "nextReview": next_review, "reviewOverdue": bool(next_review and next_review < today),
            "controls": [{"id": c.id, "ref": c.ref, "title": c.title, "state": c.state}
                         for c in sorted(links.get(r.id, []), key=lambda c: c.ref)],
            # An acceptance only counts while the score is the one that was accepted: the residual score, or the
            # inherent one for a risk accepted without a residual rating. (The standalone app compared with the
            # residual score only, so an acceptance of an unrated residual risk never showed.)
            "acceptance": ({"acceptedBy": names.get(acc.accepted_by_user_id), "acceptedAt": acc.accepted_at.isoformat() + "Z",
                            "rationale": acc.rationale, "residualScore": acc.residual_score}
                           if acc and acc.residual_score == (residual if residual is not None else inherent) else None)})
    return out


def _rating(v: Any, top: int, what: str) -> int | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not float(v).is_integer() or not 1 <= v <= top:
        raise _error(f"{what} must be between 1 and {top}.")
    return int(v)


def _derive_status(il: int | None, ii: int | None, treatment: str | None) -> str:
    if treatment:
        return "treatment_planned"
    if il is not None and ii is not None:
        return "assessed"
    return "identified"


def _text(v: Any) -> str | None:
    return (js_trim(v)[:4000] or None) if isinstance(v, str) else None


def save_risk(db: Session, tenant_id: str, actor: str, data: dict, members: set[str],
              row: IsmsRisk | None = None) -> IsmsRisk:
    """Creates or updates a risk. Refs are R-001, R-002 and so on. A change to the accepted score (the residual rating,
    or the inherent one when there is no residual rating) or to the owner ends any acceptance."""
    title = js_trim(str(data.get("title") or ""))
    if not title:
        raise _error("Give the risk a title.")
    owner = data.get("ownerId") or None
    if owner and owner not in members:
        raise _error("The owner must be a member of this organization.")
    m, _ = get_method(db, tenant_id)
    il = _rating(data.get("inherentLikelihood"), len(m.likelihood_scale), "Inherent likelihood")
    ii = _rating(data.get("inherentImpact"), len(m.impact_scale), "Inherent impact")
    rl = _rating(data.get("residualLikelihood"), len(m.likelihood_scale), "Residual likelihood")
    ri = _rating(data.get("residualImpact"), len(m.impact_scale), "Residual impact")
    treatment = data.get("treatment") if data.get("treatment") in TREATMENTS else None
    asset_ids = [str(a) for a in (data.get("assetIds") or [])]
    if asset_ids:
        found = set(db.execute(select(IsmsAsset.id).where(IsmsAsset.tenant_id == tenant_id,
                                                          IsmsAsset.id.in_(asset_ids))).scalars())
        if found != set(asset_ids):
            raise _error("One of the chosen assets does not exist.")
    values = {"title": title[:300], "description": _text(data.get("description")), "threat": _text(data.get("threat")),
              "vulnerability": _text(data.get("vulnerability")), "owner_user_id": owner, "asset_ids": asset_ids,
              "inherent_likelihood": il, "inherent_impact": ii, "treatment": treatment,
              "treatment_plan": _text(data.get("treatmentPlan")), "residual_likelihood": rl, "residual_impact": ri}
    status = _derive_status(il, ii, treatment)
    if row is None:
        refs = db.execute(select(IsmsRisk.ref).where(IsmsRisk.tenant_id == tenant_id)).scalars()
        n = max((int(r[2:]) for r in refs if re.fullmatch(r"R-\d+", r)), default=0) + 1
        row = IsmsRisk(tenant_id=tenant_id, ref=f"R-{n:03d}", status=status, updated_by=actor,
                       next_review=date.fromisoformat(maths.next_review_date(_today(), m.review_months)),
                       **values)
        db.add(row)
        db.flush()
        audit.record(db, actor, "isms.risk_added", row.ref, tenant_id, id=row.id, title=row.title)
        return row
    keep_accepted = (row.status == "accepted" and (row.residual_likelihood, row.residual_impact, row.owner_user_id)
                     == (rl, ri, owner))
    if keep_accepted and rl is None and ri is None:  # accepted on the inherent score, so that must not change either
        keep_accepted = (row.inherent_likelihood, row.inherent_impact) == (il, ii)
    for k, v in values.items():
        setattr(row, k, v)
    if row.status != "closed":
        row.status = "accepted" if keep_accepted else status
    row.updated_at, row.updated_by = utcnow(), actor
    audit.record(db, actor, "isms.risk_updated", row.ref, tenant_id, id=row.id, status=row.status)
    return row


def set_controls(db: Session, row: IsmsRisk, actor: str, control_ids: list[str]) -> None:
    """Replaces the controls that treat a risk (controls of the same customer only)."""
    wanted = set(db.execute(select(IsmsTenantControl.id).where(IsmsTenantControl.tenant_id == row.tenant_id,
                                                               IsmsTenantControl.id.in_(control_ids))).scalars())
    if wanted != set(control_ids):
        raise _error("One of the chosen controls does not exist.")
    current = set(db.execute(select(IsmsRiskControl.tenant_control_id)
                             .where(IsmsRiskControl.risk_id == row.id)).scalars())
    if current == wanted:
        return
    db.execute(delete(IsmsRiskControl).where(IsmsRiskControl.risk_id == row.id,
                                             IsmsRiskControl.tenant_control_id.notin_(wanted)))
    for cid in wanted - current:
        db.add(IsmsRiskControl(tenant_id=row.tenant_id, risk_id=row.id, tenant_control_id=cid, updated_by=actor))
    audit.record(db, actor, "isms.risk_controls_set", row.ref, row.tenant_id, controls=sorted(wanted))


def accept(db: Session, row: IsmsRisk, actor: str, user_id: str, rationale: str) -> None:
    """The risk owner accepts the residual risk (6.1.3): who, when, score and rationale. Above appetite a fuller
    rationale is needed."""
    view = risk_views(db, row.tenant_id, row.id)[0]
    if row.owner_user_id != user_id:
        raise _error("Only the risk owner can accept this risk.", 403)
    score = view["residualScore"] if view["residualScore"] is not None else view["inherentScore"]
    if score is None:
        raise _error("Assess the risk before accepting it.")
    if not row.treatment:
        raise _error("Choose a treatment before accepting the residual risk.")
    text = js_trim(rationale or "")[:4000]
    if not text:
        raise _error("Give a rationale for accepting this risk.")
    if not view["withinAppetite"] and len(text) < 40:
        raise _error("This risk is above appetite. Explain in more detail (at least 40 characters) why it is "
                     "accepted.")
    m, _ = get_method(db, row.tenant_id)
    review = date.fromisoformat(maths.next_review_date(_today(), m.review_months))
    db.add(IsmsRiskAcceptance(tenant_id=row.tenant_id, risk_id=row.id, accepted_by_user_id=user_id,
                              residual_score=int(score), rationale=text, expires_at=review, updated_by=actor))
    row.status, row.next_review, row.updated_at, row.updated_by = "accepted", review, utcnow(), actor
    audit.record(db, actor, "isms.risk_accepted", row.ref, row.tenant_id, score=score, rationale=text)
    from .notify import emit
    emit(db, row.tenant_id, "isms.risk_accepted", id=row.id, ref=row.ref, title=row.title, score=score,
         reviewBy=review.isoformat() if review else None)


def snapshot(db: Session, tenant_id: str, actor: str, user_id: str, reason: str = "manual") -> IsmsRiskSnapshot:
    """A dated copy of the whole risk assessment (8.2 evidence)."""
    m, version = get_method(db, tenant_id)
    now = utcnow()
    row = IsmsRiskSnapshot(tenant_id=tenant_id, taken_at=now, taken_by_user_id=user_id, reason=reason[:200],
                           payload={"method": method_dict(m, version), "risks": risk_views(db, tenant_id),
                                    "takenAt": now.isoformat() + "Z"}, updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.risk_snapshot_taken", reason[:200], tenant_id, id=row.id,
                 risks=len(row.payload["risks"]))
    return row


def heat_map(db: Session, tenant_id: str, residual: bool = True) -> dict:
    m, _ = get_method(db, tenant_id)
    pairs = [((r.residual_likelihood, r.residual_impact) if residual and r.residual_likelihood is not None
              else (r.inherent_likelihood, r.inherent_impact))
             for r in db.execute(select(IsmsRisk).where(IsmsRisk.tenant_id == tenant_id,
                                                        IsmsRisk.status != "closed")).scalars()]
    grid, unrated = maths.heat_map(m, pairs)
    return {"grid": grid, "unrated": unrated, "likelihood": [p.label for p in m.likelihood_scale],
            "impact": [p.label for p in m.impact_scale]}
