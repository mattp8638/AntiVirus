from fastapi import FastAPI
from .api import router as siem_router
from .db import init_db

app = FastAPI(title="SIEM Service")
app.include_router(siem_router, prefix="/siem")


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}
