from fastapi import FastAPI
from .db import init_db
from .api import router as auditing_router

app = FastAPI(title="Auditing Service")

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(auditing_router)
