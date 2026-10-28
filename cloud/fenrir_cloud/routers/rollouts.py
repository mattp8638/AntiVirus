"""Staged agent rollouts (AGT-04): list, pause, resume, advance and emergency-stop. Platform administrators only:
a rollout affects every customer's devices."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import rollouts
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import AgentRollout

router = APIRouter(prefix="/api/console/agent-rollouts", tags=["Agent rollouts"])


@router.get("")
def list_rollouts(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    rows = db.execute(select(AgentRollout).order_by(AgentRollout.started_at.desc()).limit(50)).scalars().all()
    for row in rows:
        rollouts.evaluate(db, row)
    db.commit()
    return {"stages": list(rollouts.STAGES), "rollouts": [rollouts.view(db, r) for r in rows]}


class RolloutAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["pause", "resume", "advance", "stop"]
    reason: str = Field(default="", max_length=300)


@router.post("/{rollout_id}/action")
def rollout_action(rollout_id: str, body: RolloutAction, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("platform")
    row = db.get(AgentRollout, rollout_id)
    if row is None:
        raise HTTPException(404, "Rollout not found")
    try:
        rollouts.act(db, row, body.action, principal.actor, body.reason.strip())
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return rollouts.view(db, row)
