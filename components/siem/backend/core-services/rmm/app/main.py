from fastapi import FastAPI
from .db import init_db
from .api import router as rmm_router

app = FastAPI(title="RMM Service")

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(rmm_router)
