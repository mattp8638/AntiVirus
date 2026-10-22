# RMM Service

This service provides Remote Monitoring & Management features: configuration profiles, patch management, scripted jobs, deployments, remote sessions and evidence capture.

Run locally:

1. Install dependencies from `requirements.txt`.
2. Start with `uvicorn core-services.rmm.app.main:app --port 8020 --reload`.

Environment variables:
- `RMM_DATABASE_URL` - DB connection string (default sqlite `sqlite:///./rmm.db`)
- `PSA_BASE_URL` - PSA API base URL (default `http://localhost:8001`)
