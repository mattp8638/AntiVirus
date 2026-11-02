import os

RMM_DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("RMM_DATABASE_URL", "postgresql://tamsilsiem:1792BigDirtyDykes!@10.252.0.25:5432/tamsilcmssiem?sslmode=require")
PSA_BASE_URL = os.getenv("PSA_BASE_URL", "http://localhost:8001")
SERVICE_NAME = "rmm"
