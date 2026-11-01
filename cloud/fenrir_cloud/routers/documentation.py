"""Versioned KB documents and tenant-bound encrypted credentials."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session
from .. import audit, autodoc, crypto, ratelimit, documentation
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant, require_reauth
from ..models import Configuration, DocumentRevision, KbArticle, Tenant, VaultCredential, new_id, utcnow
from ..serialize import to_dict

router = APIRouter(prefix="/api/console", tags=["Documentation and vault"])
crypto.register_encrypted(VaultCredential, "ciphertext", lambda row: f"vault:{row.tenant_id}:{row.id}")

class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    name: str = Field(min_length=1, max_length=200)
    username: str = Field(default="", max_length=200)
    url: str = Field(default="", max_length=1000)
    notes: str = Field(default="", max_length=10000)
    secret: str = Field(min_length=1, max_length=65536)
    configurationId: str | None = None
    expiresAt: datetime | None = None

class CredentialUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    username: str | None = Field(default=None, max_length=200)
    url: str | None = Field(default=None, max_length=1000)
    notes: str | None = Field(default=None, max_length=10000)
    secret: str | None = Field(default=None, min_length=1, max_length=65536)
    archived: bool | None = None


def owned(db, model, ident, principal):
    row = db.get(model, ident)
    if row is None:
        raise HTTPException(404, "Not found")
    principal.check_tenant(row.tenant_id)
    return row

@router.get("/documentation/templates")
def templates(principal: Principal = Depends(current_principal)):
    principal.require("read")
    return documentation.TEMPLATES

def _customer(db, tenant_id, principal):
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return tenant

@router.get("/documentation/auto")
def auto_documentation(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Per customer: whether generated documentation is on, when it last refreshed, and its pages."""
    principal.require("read")
    scope = scoped_tenant(principal, tenant_id)
    articles = db.scalars(select(KbArticle).where(KbArticle.tenant_id.in_(scope), KbArticle.category == autodoc.CATEGORY)).all()
    out = []
    for tenant in db.scalars(select(Tenant).where(Tenant.id.in_(scope), Tenant.kind == "customer").order_by(Tenant.name)):
        config = (tenant.settings or {}).get("autoDocumentation") or {}
        out.append({"tenantId": tenant.id, "tenantName": tenant.name, "enabled": bool(config.get("enabled")),
                    "lastRefreshAt": config.get("lastRefreshAt"),
                    "pages": [{"id": a.id, "title": a.title, "updatedAt": a.updated_at.isoformat() + "Z" if a.updated_at else None}
                              for a in articles if a.tenant_id == tenant.id]})
    return out

@router.put("/documentation/auto/{tenant_id}")
def set_auto_documentation(tenant_id: str, body: dict, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    tenant = _customer(db, tenant_id, principal)
    config = {**((tenant.settings or {}).get("autoDocumentation") or {}), "enabled": bool(body.get("enabled"))}
    tenant.settings = {**(tenant.settings or {}), "autoDocumentation": config}
    audit.record(db, principal.actor, "documentation.auto.configured", tenant.name, tenant.id, enabled=config["enabled"])
    db.commit()
    return config

@router.post("/documentation/auto/{tenant_id}/refresh")
def refresh_auto_documentation(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Regenerate the customer's documentation pages now. Engineer notes below the notes line are kept."""
    principal.require("crm")
    tenant = _customer(db, tenant_id, principal)
    results = autodoc.refresh(db, tenant, principal.actor)
    config = (tenant.settings or {}).get("autoDocumentation") or {}
    tenant.settings = {**(tenant.settings or {}), "autoDocumentation": {**config, "lastRefreshAt": utcnow().isoformat()}}
    db.commit()
    return results

@router.get("/documentation/{article_id}/revisions")
def revisions(article_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    owned(db, KbArticle, article_id, principal)
    return [to_dict(row) for row in db.scalars(select(DocumentRevision).where(DocumentRevision.article_id == article_id)
            .order_by(DocumentRevision.created_at.desc(), DocumentRevision.id.desc()).limit(500))]

@router.post("/documentation/{article_id}/restore/{revision_id}")
def restore(article_id: str, revision_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    article = owned(db, KbArticle, article_id, principal)
    revision = owned(db, DocumentRevision, revision_id, principal)
    if revision.article_id != article.id:
        raise HTTPException(404, "Revision not found")
    documentation.snapshot(db, article, principal.actor)
    for key, value in revision.snapshot.items():
        setattr(article, key, value)
    article.updated_at = utcnow()
    documentation.snapshot(db, article, principal.actor)
    audit.record(db, principal.actor, "documentation.restored", article.id, article.tenant_id, revision=revision.id)
    db.commit()
    return to_dict(article)

@router.get("/vault/credentials")
def credentials(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("vault")
    return [to_dict(row) for row in db.scalars(select(VaultCredential).where(VaultCredential.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                                              .order_by(VaultCredential.name).limit(2000))]

@router.post("/vault/credentials")
def create(body: CredentialInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("vault")
    principal.check_tenant(body.tenantId)
    if body.configurationId:
        config = db.get(Configuration, body.configurationId)
        if config is None or config.account_tenant_id != body.tenantId:
            raise HTTPException(404, "Configuration not found in this tenant")
    row = VaultCredential(id=new_id("cred"), tenant_id=body.tenantId, name=body.name, username=body.username,
                          url=body.url, notes=body.notes, configuration_id=body.configurationId,
                          expires_at=(body.expiresAt.astimezone(timezone.utc).replace(tzinfo=None) if body.expiresAt.tzinfo else body.expiresAt) if body.expiresAt else None, updated_by=principal.actor)
    row.ciphertext = crypto.encrypt(body.secret, f"vault:{row.tenant_id}:{row.id}")
    db.add(row)
    audit.record(db, principal.actor, "vault.created", row.id, row.tenant_id)
    db.commit()
    return to_dict(row)

@router.patch("/vault/credentials/{credential_id}")
def update(credential_id: str, body: CredentialUpdate, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("vault")
    row = owned(db, VaultCredential, credential_id, principal)
    require_reauth(request, principal)
    for key, value in body.model_dump(exclude_none=True).items():
        if key == "secret":
            row.ciphertext = crypto.encrypt(value, f"vault:{row.tenant_id}:{row.id}")
        else:
            setattr(row, key, value)
    row.updated_at, row.updated_by = utcnow(), principal.actor
    audit.record(db, principal.actor, "vault.updated", row.id, row.tenant_id, fields=list(body.model_fields_set))
    db.commit()
    return to_dict(row)

@router.delete("/vault/credentials/{credential_id}")
def delete_credential(credential_id: str, request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Destroy a stored credential (fresh sign-in required). The audit log keeps that it existed and who removed it."""
    principal.require("vault")
    row = owned(db, VaultCredential, credential_id, principal)
    require_reauth(request, principal)
    db.delete(row)
    audit.record(db, principal.actor, "vault.deleted", row.id, row.tenant_id, name=row.name)
    db.commit()
    return {"ok": True}

@router.post("/vault/credentials/{credential_id}/reveal")
def reveal(credential_id: str, request: Request, response: Response, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("vault")
    row = owned(db, VaultCredential, credential_id, principal)
    require_reauth(request, principal)
    ratelimit.check(f"vault-reveal:{principal.user.id}", 20, 300)
    if row.archived:
        raise HTTPException(409, "Restore this archived credential before revealing it")
    secret = crypto.decrypt(row.ciphertext, f"vault:{row.tenant_id}:{row.id}")
    audit.record(db, principal.actor, "vault.revealed", row.id, row.tenant_id)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"secret": secret}
