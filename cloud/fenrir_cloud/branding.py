"""MSP branding: the name, logo, colours and contact details customers see.

One brand per MSP, kept on the MSP's root tenant (``Tenant.settings["branding"]``). Customers inherit their MSP's brand.
It is used by:

- reports (HTML and PDF): logo, name, colours, contact line and footer;
- the console and customer portal: sign-in page, sidebar, accent colour and page title (``/api/console/auth/branding``
  is public, so the sign-in page can show it before anyone signs in);
- the Windows agent window: the brand name when the policy leaves ``experience.brandName`` at its default.

Logos are re-encoded server-side as PNG (at most 600x200 pixels), so whatever was uploaded (metadata, an embedded
script in a polyglot file, a decompression bomb) never reaches a browser or a PDF as-is. Only PNG and JPEG are
accepted; SVG is refused because it can carry script.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Tenant

DEFAULTS = {
    "companyName": "Fenrir",
    "tagline": "Unified security platform",
    "primaryColour": "#3b82f6",
    "accentColour": "#a855f7",
    "supportEmail": "",
    "supportPhone": "",
    "website": "",
    "reportFooter": "",
}
TEXT_LIMITS = {"companyName": 80, "tagline": 120, "supportEmail": 200, "supportPhone": 40, "website": 200, "reportFooter": 400}
MAX_UPLOAD = 2 * 1024 * 1024  # the upload; what is kept is the small re-encoded PNG
MAX_PIXELS = 4000 * 4000
LOGO_BOX = (600, 200)
_COLOUR = re.compile(r"#[0-9a-fA-F]{6}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def msp_of(db: Session, tenant_id: str | None) -> Tenant | None:
    """The MSP tenant whose brand applies to ``tenant_id`` (the tenant itself when it is an MSP)."""
    tenant = db.get(Tenant, tenant_id) if tenant_id else None
    while tenant is not None and tenant.kind != "msp" and tenant.parent_id:
        tenant = db.get(Tenant, tenant.parent_id)
    return tenant


def default_msp(db: Session) -> Tenant | None:
    """The install's own MSP (the root MSP tenant): its brand is the one the public sign-in page shows."""
    return db.execute(select(Tenant).where(Tenant.kind == "msp", Tenant.parent_id.is_(None))
                      .order_by(Tenant.created_at)).scalars().first()


def _stored(tenant: Tenant | None) -> dict:
    value = ((tenant.settings or {}).get("branding") if tenant else None) or {}
    return value if isinstance(value, dict) else {}


def text_on(colour: str) -> str:
    """White text when it is readable on ``colour`` (WCAG contrast of at least 3:1, the minimum for buttons and large
    text), otherwise near-black."""
    def channel(hex_pair: str) -> float:
        c = int(hex_pair, 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(colour[i:i + 2]) for i in (1, 3, 5))
    luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
    return "#ffffff" if 1.05 / (luminance + 0.05) >= 3.0 else "#111827"


def get(db: Session, tenant_id: str | None = None, *, msp: Tenant | None = None) -> dict:
    """The brand for a tenant (or the install's default MSP), with defaults filled in. ``logo`` is base64 PNG or None."""
    msp = msp or (msp_of(db, tenant_id) if tenant_id else default_msp(db))
    stored = _stored(msp)
    brand = {key: (stored.get(key) or default) for key, default in DEFAULTS.items()}
    if not stored.get("companyName") and msp is not None and msp.name:
        brand["companyName"] = msp.name
    brand["onPrimary"] = text_on(brand["primaryColour"])
    brand["logo"] = stored.get("logo") or None
    brand["logoVersion"] = hashlib.sha256(brand["logo"].encode()).hexdigest()[:12] if brand["logo"] else None
    brand["customised"] = bool(stored)
    return brand


def logo_bytes(brand: dict) -> bytes | None:
    try:
        return base64.b64decode(brand["logo"]) if brand.get("logo") else None
    except (ValueError, TypeError):
        return None


def public(brand: dict) -> dict:
    """What anyone may see before signing in: no contact details, no footer, and the MSP's tenant name only once
    someone has chosen to brand the install."""
    return {"companyName": brand["companyName"] if brand["customised"] else DEFAULTS["companyName"], "tagline": brand["tagline"], "primaryColour": brand["primaryColour"],
            "accentColour": brand["accentColour"], "onPrimary": brand["onPrimary"],
            "logoUrl": f"/api/console/auth/branding/logo?v={brand['logoVersion']}" if brand["logo"] else None}


def contact_line(brand: dict) -> str:
    return " · ".join(v for v in (brand.get("supportEmail"), brand.get("supportPhone"), brand.get("website")) if v)


def validate(body: dict) -> dict:
    """Checked, cleaned settings from a request body. Unknown keys are ignored; empty values fall back to defaults."""
    if not isinstance(body, dict):
        raise ValueError("Send the branding settings as an object")
    clean: dict = {}
    for key, limit in TEXT_LIMITS.items():
        if key not in body:
            continue
        value = body[key]
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"{key} must be text")
        value = _CONTROL.sub(" ", value).strip()
        if len(value) > limit:
            raise ValueError(f"{key} can be at most {limit} characters")
        clean[key] = value
    for key in ("primaryColour", "accentColour"):
        if key in body and body[key] not in (None, ""):
            if not isinstance(body[key], str) or not _COLOUR.fullmatch(body[key]):
                raise ValueError(f"{key} must be a colour like #1d4ed8")
            clean[key] = body[key].lower()
        elif key in body:
            clean[key] = ""
    if clean.get("supportEmail") and not _EMAIL.fullmatch(clean["supportEmail"]):
        raise ValueError("supportEmail must be an email address")
    if clean.get("website") and not clean["website"].startswith("https://"):
        raise ValueError("website must start with https://")
    return clean


def normalise_logo(data: bytes) -> str:
    """Base64 of a safe PNG re-encoding of an uploaded PNG or JPEG logo. Raises ValueError with a reason."""
    if not data:
        raise ValueError("The logo file is empty")
    if len(data) > MAX_UPLOAD:
        raise ValueError("The logo must be at most 2 MB")
    if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff")):
        raise ValueError("The logo must be a PNG or JPEG image (SVG is not accepted)")
    from PIL import Image

    try:
        with Image.open(io.BytesIO(data)) as probe:
            if probe.width * probe.height > MAX_PIXELS:
                raise ValueError("The logo is too large; use an image under 4000 x 4000 pixels")
            probe.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            image = image.convert("RGBA")
            image.thumbnail(LOGO_BOX)
            out = io.BytesIO()
            image.save(out, format="PNG", optimize=True)
    except ValueError:
        raise
    except Exception as exc:  # Pillow raises many types for damaged files
        raise ValueError("The logo could not be read as an image") from exc
    return base64.b64encode(out.getvalue()).decode()


def save(msp: Tenant, values: dict) -> None:
    settings = dict(msp.settings or {})
    stored = dict(_stored(msp))
    for key, value in values.items():
        if value in ("", None):
            stored.pop(key, None)
        else:
            stored[key] = value
    settings["branding"] = stored
    msp.settings = settings
