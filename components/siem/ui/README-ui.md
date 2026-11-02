# UI

Scope: Unified user interface.

Constraints:
- No direct DB access.
- All data access via core-services APIs.
- No direct network calls outside /transport.

## Local development

```bash
npm install
npm run dev
```

Open `http://localhost:5173` to view the dashboard.

### Transport integration

Set the transport base URL to proxy core-services APIs:

```bash
export VITE_TRANSPORT_BASE_URL="http://localhost:8081"
```

### Direct service overrides

You can also bypass the transport gateway in development by setting per-service base URLs. For example:

```bash
export VITE_PSA_BASE_URL="http://localhost:8001"
export VITE_EDR_BASE_URL="http://localhost:8003"
export VITE_SIEM_BASE_URL="http://localhost:8002"
export VITE_INGESTION_BASE_URL="http://localhost:8000"
export VITE_RMM_BASE_URL="http://localhost:8020"
export VITE_VULNERABILITY_BASE_URL="http://localhost:8004"
export VITE_AUDITING_BASE_URL="http://localhost:8010"
```

When a per-service `VITE_<SERVICE>_BASE_URL` is present, the UI will call that service directly; otherwise it will route requests via the transport gateway configured by `VITE_TRANSPORT_BASE_URL` (or `/transport` by default).
