import smtplib
from email.mime.text import MIMEText
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from modules.storage import (
    SecretStoreError,
    get_all_settings,
    get_settings_namespace,
    save_audit_event,
    save_setting,
)

router = APIRouter()


class MailConnectorSettings(BaseModel):
    provider: str = Field(..., examples=["smtp", "m365_graph", "google_workspace"])
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    sender_address: Optional[str] = None
    connected_domain: str


class IOCProviderSettings(BaseModel):
    name: str
    provider_type: str
    api_key: Optional[str] = None
    enabled: bool = True


class EmailValidationSettings(BaseModel):
    allow_domains: list[str] = []
    trusted_senders: list[str] = []
    blocked_senders: list[str] = []
    blocked_domains: list[str] = []


def _mask_mail(mail: dict) -> dict:
    masked = dict(mail)
    if masked.get("password"):
        masked["password"] = "***masked***"
    return masked


def _load_mail_settings(include_secrets: bool = False) -> dict:
    mail = get_settings_namespace("mail", include_secrets=include_secrets)
    if not include_secrets and mail.get("password") not in (None, ""):
        mail["password"] = "***masked***"
    return mail


def _load_ioc_providers() -> dict:
    providers = get_settings_namespace("ioc_providers", include_secrets=False)
    for key, value in list(providers.items()):
        if key.endswith("__api_key"):
            base_name = key[: -len("__api_key")]
            base_provider = providers.get(base_name)
            if isinstance(base_provider, dict):
                base_provider["api_key"] = "***masked***"
            providers.pop(key, None)
    return providers


def _load_email_validation() -> dict:
    return get_settings_namespace("email_validation", include_secrets=False)


@router.get("/")
def get_settings():
    return {
        "mail": _load_mail_settings(include_secrets=False),
        "ioc_providers": _load_ioc_providers(),
        "email_validation": _load_email_validation(),
        "metadata": {"persistent": True, "secrets_masked": True},
    }


@router.post("/mail")
def save_mail_settings(settings: MailConnectorSettings):
    data = settings.model_dump()
    try:
        for key in ["host", "port", "username", "sender_address", "connected_domain", "provider", "tenant_id", "client_id"]:
            if data.get(key) is not None:
                save_setting("mail", key, data[key], secret=False)
        if data.get("password"):
            save_setting("mail", "password", data["password"], secret=True)
    except SecretStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    save_audit_event(action="settings_saved", entity_type="settings", entity_id="mail", details={"provider": data.get("provider")})
    return {"status": "saved", "mail": _mask_mail(get_settings_namespace("mail", include_secrets=False))}


@router.post("/mail/test")
def test_mail():
    mail = get_settings_namespace("mail", include_secrets=True)
    if not mail:
        raise HTTPException(status_code=400, detail="No mail configuration saved")
    required = ["host", "port", "username", "password", "sender_address"]
    missing = [field for field in required if not mail.get(field)]
    if missing:
        raise HTTPException(status_code=400, detail={"message": "Missing mail settings", "missing": missing})

    msg = MIMEText("Sentinel SMTP test email. If you received this, the configured email connection works.")
    msg["Subject"] = "Sentinel SMTP Test"
    msg["From"] = mail["sender_address"]
    msg["To"] = mail["sender_address"]

    with smtplib.SMTP(mail["host"], int(mail["port"]), timeout=20) as server:
        server.starttls()
        server.login(mail["username"], mail["password"])
        server.send_message(msg)

    save_audit_event(action="settings_tested", entity_type="settings", entity_id="mail")
    return {"status": "email sent", "to": mail["sender_address"]}


@router.post("/ioc-provider")
def save_ioc_provider(settings: IOCProviderSettings):
    data = settings.model_dump()
    provider = {key: value for key, value in data.items() if key != "api_key"}
    try:
        save_setting("ioc_providers", settings.name, provider, secret=False)
        if data.get("api_key"):
            save_setting("ioc_providers", f"{settings.name}__api_key", data["api_key"], secret=True)
    except SecretStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    save_audit_event(action="settings_saved", entity_type="settings", entity_id=f"ioc_providers:{settings.name}", details={"provider_type": data.get("provider_type")})
    provider = get_settings_namespace("ioc_providers", include_secrets=False).get(settings.name, provider)
    if isinstance(provider, dict) and provider.get("api_key"):
        provider["api_key"] = "***masked***"
    elif data.get("api_key"):
        provider["api_key"] = "***masked***"
    return {"status": "saved", "provider": provider}


@router.post("/email-validation")
def save_email_validation(settings: EmailValidationSettings):
    data = settings.model_dump()
    for key, value in data.items():
        save_setting("email_validation", key, value, secret=False)
    save_audit_event(action="settings_saved", entity_type="settings", entity_id="email_validation", details=data)
    return {"status": "saved", "email_validation": get_settings_namespace("email_validation", include_secrets=False)}