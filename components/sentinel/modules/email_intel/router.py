from fastapi import APIRouter
from pydantic import BaseModel, EmailStr

router = APIRouter()

KNOWN_BAD_DOMAINS = {"malicious.com", "phish-test.com"}
KNOWN_TRUSTED_DOMAINS = {"microsoft.com", "google.com"}

class EmailCheck(BaseModel):
    email: EmailStr

@router.post("/check")
def check_email(data: EmailCheck):
    domain = data.email.split("@")[-1].lower()

    if domain in KNOWN_BAD_DOMAINS:
        return {"email": data.email, "classification": "malicious", "confidence": 90}

    if domain in KNOWN_TRUSTED_DOMAINS:
        return {"email": data.email, "classification": "trusted", "confidence": 90}

    return {"email": data.email, "classification": "unknown", "confidence": 40}
