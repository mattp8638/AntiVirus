from fastapi import FastAPI
from .api import router as edr_router
from .db import init_db

app = FastAPI(title="EDR Service")
app.include_router(edr_router, prefix="/edr")


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}
