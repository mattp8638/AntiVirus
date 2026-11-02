# Dev Build SIEM Platform

**Enterprise Security Information and Event Management (SIEM) + Endpoint Detection and Response (EDR)**
### This is an ongoing development work, I have yet to master and finalise, but hopefully nearing the end soon
## Features

### SIEM Core
- 📊 **Log Collection & Aggregation** from multiple sources
- 🔍 **Real-time Event Correlation** with custom rules
- 🎯 **Threat Detection** using ML and signatures
- 📈 **Security Analytics** and dashboards
- 🚨 **Alerting & Incident Response** automation
- 📋 **Compliance Reporting** (PCI-DSS, HIPAA, SOC2)

### EDR/XDR (Sentinel)
- 🛡️ **Endpoint Protection** on Windows endpoints
- 👁️ **Real-time Telemetry** via ETW (Event Tracing for Windows)
- 🦠 **Malware Detection** with ML-based threat scoring
- 🔬 **Behavioral Analysis** of processes and files
- 🌐 **Network Monitoring** and C2 detection
- 💉 **Memory Scanning** for injection attacks
- 🚀 **Automated Response** (isolate, block, quarantine)

---

## Architecture

```
Endpoints        SIEM Backend          Dashboard
   |
   | Sentinel Agent (Rust)
   |
   ├─→ ETW Monitor
   ├─→ Process Monitor      →  FastAPI         →  React UI
   ├─→ File Monitor         →  PostgreSQL     →  /edr/*
   ├─→ Network Monitor      →  Correlation    →  Real-time
   └─→ ML Detector          →  Alerting       →  Dashboards
```

---

## Quick Start

### 1. Deploy SIEM Backend

```bash
git clone https://github.com/zy538324/Dev Build-SIEM.git
cd Dev Build-SIEM

# Backend
cd backend
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Deploy Dashboard

```bash
# UI
cd ui
npm install
npm run build
npm run preview
```

### 3. Deploy EDR Agent

```powershell
# Build agent
cd edr-agent
cargo build --release

# Configure
cp config.example.json config.json
# Edit config.json with your SIEM endpoint

# Install
sc.exe create Dev BuildSentinel binPath= "C:\\Path\\To\\sentinel-agent.exe"
sc.exe start Dev BuildSentinel
```

---

## Components

### Backend (`/backend`)
- Python/FastAPI
- PostgreSQL database
- REST API for agents and UI
- Event correlation engine
- Threat intelligence integration

### Dashboard (`/ui`)
- React + TypeScript
- Real-time updates
- EDR management pages:
  - `/edr/dashboard` - Overview
  - `/edr/agents` - Endpoint management
  - `/edr/threats` - Threat detection
  - `/edr/events` - Event timeline

### EDR Agent (`/edr-agent`)
- Rust (for performance & safety)
- Windows service
- Real-time telemetry collection
- Reports to SIEM backend API

### Data Model (`/data-model`)
- Database schemas
- Event normalization
- MITRE ATT&CK mapping

---

## Documentation

- [EDR Integration Guide](docs/EDR_INTEGRATION.md)
- [API Documentation](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Security Policy](SECURITY.md)

---

## API Endpoints

### SIEM Core
```
GET    /api/v1/events              - Query security events
POST   /api/v1/events              - Ingest events
GET    /api/v1/alerts              - Get alerts
POST   /api/v1/incidents           - Create incident
```

### EDR
```
POST   /api/v1/edr/agents/register - Register agent
GET    /api/v1/edr/agents          - List agents
POST   /api/v1/edr/events          - Ingest EDR events
GET    /api/v1/edr/threats         - Get threats
POST   /api/v1/edr/threats/{id}/respond - Respond to threat
```

---

## Performance

**SIEM Backend:**
- 50,000+ events/second (single instance)
- 500,000+ events/second (with Kafka)
- Sub-second query response

**EDR Agent:**
- 2-5% CPU usage
- 150MB memory footprint
- <1ms detection latency

---

## Security

- 🔒 **TLS encryption** for all communication
- 🔑 **API key authentication** for agents
- 👤 **RBAC** (Role-Based Access Control)
- 📝 **Audit logging** of all actions
- 🛡️ **Secure by default** configuration

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

## Support

- 📧 Email: security@Dev Build.com
- 🐛 Issues: [GitHub Issues](https://github.com/zy538324/Dev Build-SIEM/issues)
- 📚 Docs: [Documentation](https://docs.Dev Build.com)

---

## Roadmap

- [x] SIEM core functionality
- [x] EDR agent (Windows)
- [x] Real-time dashboard
- [x] Threat detection (ML)
- [ ] EDR agent (Linux)
- [ ] EDR agent (macOS)
- [ ] SOAR automation
- [ ] Threat hunting tools
- [ ] Cloud integrations (AWS, Azure, GCP)

---

**Built with ❤️ by the Dev Build Security Team**
