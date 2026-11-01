"""Search everything from one box (Ctrl+K): devices, customers, tickets, staff, contacts, vulnerabilities and scripts.

Only what the caller can already see: their customers' records, the shared script library, and staff only for those
who manage users. Each kind returns a few best matches; the console adds its own pages to the list.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends
from sqlalchemy import Integer, func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..models import Contact, Device, Script, Tenant, Ticket, User, Vulnerability

router = APIRouter(prefix="/api/console", tags=["Search"])

PER_KIND = 6
TICKET_NUMBER = re.compile(r"^#?(\d{1,9})$")


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/search")
def search(q: str = "", principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    q = q.strip()[:100]
    if len(q) < 2:
        return {"query": q, "results": []}
    like = f"%{_escape(q.lower())}%"
    contains = lambda column: func.lower(column).like(like, escape="\\")  # noqa: E731
    scope = list(principal.tenant_ids)
    names = dict(db.execute(select(Tenant.id, Tenant.name).where(Tenant.id.in_(scope))).all())
    results: list[dict] = []

    for d in db.execute(select(Device).where(Device.tenant_id.in_(scope), or_(
            contains(Device.hostname), contains(Device.serial_number), contains(Device.ip_address)))
            .order_by(Device.hostname).limit(PER_KIND)).scalars():
        results.append({"kind": "device", "id": d.id, "title": d.hostname, "link": f"/devices/{d.id}",
                        "subtitle": " · ".join(x for x in (names.get(d.tenant_id, ""), d.platform, d.ip_address) if x)})

    for t in db.execute(select(Tenant).where(Tenant.id.in_(scope), Tenant.kind == "customer", contains(Tenant.name))
                        .order_by(Tenant.name).limit(PER_KIND)).scalars():
        results.append({"kind": "company", "id": t.id, "title": t.name, "subtitle": "Customer", "link": f"/companies/{t.id}"})

    number = TICKET_NUMBER.match(q)
    ticket_match = Ticket.number == int(number.group(1)) if number else contains(Ticket.subject)
    for t in db.execute(select(Ticket).where(or_(Ticket.account_tenant_id.in_(scope), Ticket.tenant_id.in_(scope)), ticket_match)
                        .order_by(Ticket.created_at.desc()).limit(PER_KIND)).scalars():
        results.append({"kind": "ticket", "id": t.id, "title": f"#{t.number} {t.subject}", "link": f"/tickets/{t.id}",
                        "subtitle": " · ".join(x for x in (names.get(t.account_tenant_id or "", ""), t.status, t.assignee) if x)})

    if principal.can("configure"):
        for u in db.execute(select(User).where(User.tenant_id.in_(scope), User.role != "service",
                                               or_(contains(User.email), contains(User.name))).order_by(User.email).limit(PER_KIND)).scalars():
            results.append({"kind": "user", "id": u.id, "title": u.name or u.email, "link": "/settings?tab=Users",
                            "subtitle": f"{u.email} · {u.role.replace('_', ' ')}" + ("" if u.active else " · disabled")})

    for c in db.execute(select(Contact).where(Contact.account_tenant_id.in_(scope), or_(contains(Contact.name), contains(Contact.email)))
                        .order_by(Contact.name).limit(PER_KIND)).scalars():
        results.append({"kind": "contact", "id": c.id, "title": c.name, "link": f"/companies/{c.account_tenant_id}",
                        "subtitle": " · ".join(x for x in (c.email, names.get(c.account_tenant_id or "", "")) if x)})

    vulns = db.execute(select(Vulnerability.vuln_id, func.count(func.distinct(Vulnerability.device_id)),
                              func.max(Vulnerability.known_exploited.cast(Integer)))
                       .where(Vulnerability.tenant_id.in_(scope), contains(Vulnerability.vuln_id))
                       .group_by(Vulnerability.vuln_id).order_by(Vulnerability.vuln_id).limit(PER_KIND)).all()
    for vuln_id, devices, exploited in vulns:
        results.append({"kind": "vulnerability", "id": vuln_id, "title": vuln_id, "link": f"/vulnerabilities?q={vuln_id}",
                        "subtitle": f"{devices} device{'s' if devices != 1 else ''}" + (" · known exploited" if exploited else "")})

    for s in db.execute(select(Script).where(or_(Script.tenant_id.is_(None), Script.tenant_id.in_(scope)),
                                             or_(contains(Script.name), contains(Script.description)))
                        .order_by(Script.name).limit(PER_KIND)).scalars():
        results.append({"kind": "script", "id": s.id, "title": s.name, "link": f"/scripts?id={s.id}",
                        "subtitle": f"{s.language} · {s.category}"})
    return {"query": q, "results": results}
