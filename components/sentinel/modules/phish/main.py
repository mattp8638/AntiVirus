from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import SessionLocal, engine
from .models import Base, Domain, Campaign, Event

Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishGuard API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DomainRequest(BaseModel):
    name: str
    provider: str

class CampaignRequest(BaseModel):
    name: str
    domain: str
    users: list[str]

@app.post("/domain/connect")
def connect_domain(req: DomainRequest):
    db = SessionLocal()

    existing = db.query(Domain).filter(Domain.name == req.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already connected")

    domain = Domain(name=req.name, provider=req.provider)
    db.add(domain)
    db.commit()
    db.close()

    return {"status": "connected", "domain": req.name}

@app.post("/campaign/create")
def create_campaign(req: CampaignRequest):
    db = SessionLocal()

    domain = db.query(Domain).filter(Domain.name == req.domain).first()
    if not domain:
        raise HTTPException(status_code=403, detail="Domain not connected")

    # enforce internal-only emails
    for user in req.users:
        if not user.endswith("@" + req.domain):
            raise HTTPException(status_code=403, detail=f"External email blocked: {user}")

    campaign = Campaign(name=req.name, domain_id=domain.id)
    db.add(campaign)
    db.commit()
    db.refresh(campaign)

    # simulate sending + logging
    for user in req.users:
        db.add(Event(campaign_id=campaign.id, user=user, action="sent"))

    db.commit()
    db.close()

    return {"status": "campaign created", "campaign_id": campaign.id}

@app.get("/campaign/results/{campaign_id}")
def campaign_results(campaign_id: int):
    db = SessionLocal()
    events = db.query(Event).filter(Event.campaign_id == campaign_id).all()
    return events