# TamsilCMS SIEM + Sentinel EDR Integration Guide

## Overview

This guide covers the integration of **TamsilCMS Sentinel EDR** into the **TamsilCMS SIEM Platform**.

## Architecture

```
┌───────────────────────────────────────────┐
│          Windows Endpoints (Protected)          │
│                                                 │
│  ┌────────────────────────────────────┐  │
│  │     Sentinel EDR Agent (Rust)        │  │
│  │  ┌───────────────────────────────┐  │  │
│  │  │  ● ETW Monitor               │  │  │
│  │  │  ● Process Monitor            │  │  │
│  │  │  ● File Operations            │  │  │
│  │  │  ● Network Connections        │  │  │
│  │  │  ● Threat Detection (ML)      │  │  │
│  │  └───────────────────────────────┘  │  │
│  └────────────────────────────────────┘  │
└───────────────────────────────────────────┘
               │
               │ HTTPS/REST API
               │ POST /api/v1/edr/events
               │ POST /api/v1/edr/threats
               │ GET  /api/v1/edr/commands
               │
               v
┌───────────────────────────────────────────┐
│       TamsilCMS SIEM Backend (Python)        │
│                                                 │
│  ┌────────────────────────────────────┐  │
│  │      EDR API Endpoints              │  │
│  │  ● /edr/agents/register          │  │
│  │  ● /edr/events                    │  │
│  │  ● /edr/threats                   │  │
│  │  ● /edr/statistics                │  │
│  └────────────────────────────────────┘  │
│                                                 │
│  ┌────────────────────────────────────┐  │
│  │      PostgreSQL Database            │  │
│  │  ● edr_agents                    │  │
│  │  ● edr_events                    │  │
│  │  ● edr_threats                   │  │
│  └────────────────────────────────────┘  │
└───────────────────────────────────────────┘
               │
               │ React/WebSocket
               v
┌───────────────────────────────────────────┐
│        TamsilCMS SIEM Dashboard (React)       │
│                                                 │
│  ┌────────────────────────────────────┐  │
│  │      EDR Pages                      │  │
│  │  ● /edr/dashboard                │  │
│  │  ● /edr/agents                   │  │
│  │  ● /edr/threats                  │  │
│  │  ● /edr/events                   │  │
│  └────────────────────────────────────┘  │
└───────────────────────────────────────────┘
```

---

## Components

### 1. **Sentinel EDR Agent** (Rust)
- **Location**: `edr-agent/`
- **Purpose**: Endpoint protection and telemetry
- **Language**: Rust (for performance and safety)
- **Runs as**: Windows service

**Capabilities**:
- Real-time ETW (Event Tracing for Windows)
- Process creation/termination monitoring
- File system operations tracking
- Network connection monitoring
- Memory scanning
- ML-based threat detection

### 2. **SIEM Backend API** (Python/FastAPI)
- **Location**: `backend/app/api/endpoints/edr.py`
- **Purpose**: Ingest and manage EDR data
- **Database**: PostgreSQL

**Endpoints**:
```
POST   /api/v1/edr/agents/register    - Register new agent
GET    /api/v1/edr/agents             - List all agents
POST   /api/v1/edr/events             - Ingest telemetry events
GET    /api/v1/edr/events             - Query events
POST   /api/v1/edr/threats            - Report threat detection
GET    /api/v1/edr/threats            - Query threats
POST   /api/v1/edr/threats/{id}/respond - Respond to threat
GET    /api/v1/edr/statistics         - Get EDR stats
GET    /api/v1/edr/commands           - Get agent commands
```

### 3. **SIEM Dashboard** (React)
- **Location**: `ui/src/pages/edr/`
- **Purpose**: Visualize and manage EDR data

**Pages**:
- `/edr/dashboard` - Overview and statistics
- `/edr/agents` - Endpoint management
- `/edr/threats` - Threat detection and response
- `/edr/events` - Event timeline and search

---

## Installation

### Step 1: Deploy SIEM Backend

```bash
# Navigate to backend
cd backend

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Step 2: Deploy SIEM Dashboard

```bash
# Navigate to UI
cd ui

# Install dependencies
npm install

# Build for production
npm run build

# Start production server
npm run preview
```

### Step 3: Build Sentinel Agent

```powershell
# Navigate to agent
cd edr-agent

# Build release version
cargo build --release

# Output: target/release/sentinel-agent.exe
```

### Step 4: Configure Agent

```powershell
# Create config
cp config.example.json config.json

# Edit config.json
{
  "siem_endpoint": "https://siem.yourdomain.com",
  "api_key": "your-api-key-from-siem",
  "reporting_interval_secs": 10
}
```

### Step 5: Deploy Agent to Endpoints

```powershell
# Install as Windows service
sc.exe create TamsilCMSSentinel `
  binPath= "C:\Program Files\TamsilCMS\sentinel-agent.exe" `
  start= auto `
  DisplayName= "TamsilCMS Sentinel EDR"

# Start service
sc.exe start TamsilCMSSentinel

# Verify
sc.exe query TamsilCMSSentinel
```

---

## Data Flow

### Agent Registration
```
Agent Startup
  → POST /api/v1/edr/agents/register
  → Backend creates agent record
  → Agent receives confirmation
  → Agent starts telemetry collection
```

### Event Ingestion
```
Agent collects events (every 10s)
  → POST /api/v1/edr/events (batch of events)
  → Backend stores in edr_events table
  → Backend runs correlation rules
  → If threat detected → creates edr_threats record
  → Dashboard updates in real-time
```

### Threat Response
```
SOC Analyst sees threat in dashboard
  → Clicks "Isolate" or "Block"
  → POST /api/v1/edr/threats/{id}/respond
  → Backend queues command for agent
  → Agent polls GET /api/v1/edr/commands
  → Agent executes command
  → Agent reports result
```

---

## Database Schema

### edr_agents
```sql
CREATE TABLE edr_agents (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(255),
    ip_address VARCHAR(45),
    agent_version VARCHAR(50),
    status VARCHAR(50) DEFAULT 'online',
    last_seen TIMESTAMP DEFAULT NOW(),
    registered_at TIMESTAMP DEFAULT NOW()
);
```

### edr_events
```sql
CREATE TABLE edr_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) REFERENCES edr_agents(agent_id),
    event_type VARCHAR(100),
    timestamp TIMESTAMP DEFAULT NOW(),
    process_id INTEGER,
    process_name VARCHAR(255),
    command_line TEXT,
    severity VARCHAR(50),
    raw_data JSONB
);

CREATE INDEX idx_edr_events_agent ON edr_events(agent_id);
CREATE INDEX idx_edr_events_time ON edr_events(timestamp DESC);
CREATE INDEX idx_edr_events_severity ON edr_events(severity);
```

### edr_threats
```sql
CREATE TABLE edr_threats (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) REFERENCES edr_agents(agent_id),
    threat_type VARCHAR(100),
    threat_name VARCHAR(255),
    severity VARCHAR(50),
    status VARCHAR(50) DEFAULT 'detected',
    process_name VARCHAR(255),
    file_path TEXT,
    file_hash VARCHAR(64),
    mitre_tactics JSONB,
    mitre_techniques JSONB,
    ml_score FLOAT,
    timestamp TIMESTAMP DEFAULT NOW(),
    responded_at TIMESTAMP,
    responded_by VARCHAR(255)
);

CREATE INDEX idx_edr_threats_agent ON edr_threats(agent_id);
CREATE INDEX idx_edr_threats_severity ON edr_threats(severity);
CREATE INDEX idx_edr_threats_status ON edr_threats(status);
```

---

## API Examples

### Register Agent
```bash
curl -X POST http://localhost:8000/api/v1/edr/agents/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "agent_id": "WIN-12345-abc123",
    "hostname": "LAPTOP-01",
    "os_version": "Windows 11 Pro",
    "ip_address": "192.168.1.100",
    "agent_version": "1.0.0"
  }'
```

### Send Events
```bash
curl -X POST http://localhost:8000/api/v1/edr/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '[{
    "agent_id": "WIN-12345-abc123",
    "event_type": "process_create",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -enc ABC123...",
    "severity": "high"
  }]'
```

### Report Threat
```bash
curl -X POST http://localhost:8000/api/v1/edr/threats \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "agent_id": "WIN-12345-abc123",
    "threat_type": "malware",
    "threat_name": "Emotet",
    "severity": "critical",
    "process_name": "invoice.exe",
    "file_hash": "a1b2c3...",
    "mitre_tactics": ["TA0002"],
    "mitre_techniques": ["T1059.001"],
    "ml_score": 95.3
  }'
```

---

## Monitoring

### Check Agent Status
```powershell
# Service status
Get-Service TamsilCMSSentinel

# View logs
Get-EventLog -LogName Application -Source TamsilCMSSentinel -Newest 50
```

### Backend Metrics
```bash
# Check API health
curl http://localhost:8000/health

# View agent count
curl http://localhost:8000/api/v1/edr/statistics
```

---

## Scaling

### High Volume Deployments

**1,000+ Endpoints:**
- Use message queue (RabbitMQ/Kafka) for event ingestion
- Deploy multiple backend instances behind load balancer
- Use PostgreSQL read replicas for queries
- Enable batch event processing

**10,000+ Endpoints:**
- Switch to TimescaleDB for event storage
- Use Elasticsearch for event search
- Deploy Kafka for event streaming
- Use Redis for agent command queuing

---

## Troubleshooting

### Agent Not Connecting
```powershell
# Check network
Test-NetConnection -ComputerName siem.domain.com -Port 8000

# Check firewall
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*TamsilCMS*"}

# View agent logs
Get-Content "C:\ProgramData\TamsilCMS\logs\agent.log"
```

### Events Not Appearing
```bash
# Check backend logs
tail -f /var/log/tamsilcms/backend.log

# Check database
psql -d tamsilcms_siem -c "SELECT COUNT(*) FROM edr_events;"

# Check API
curl http://localhost:8000/api/v1/edr/events?limit=10
```

---

## Security Considerations

1. **API Authentication**: All agent communication uses API keys
2. **TLS Encryption**: Agent ↔ Backend uses HTTPS
3. **Agent Isolation**: Agents can be remotely isolated
4. **Audit Logging**: All actions logged
5. **RBAC**: Role-based access control for dashboard

---

## Performance

**Expected Resource Usage:**

| Component | CPU | Memory | Network |
|-----------|-----|--------|----------|
| Agent (per endpoint) | 2-5% | 150MB | 100KB/s |
| Backend (1K agents) | 20-40% | 2GB | 10MB/s |
| Database (1K agents) | 10-20% | 4GB | 5MB/s |
| Dashboard | <5% | 200MB | 1MB/s |

**Event Throughput:**
- Single backend instance: ~50,000 events/second
- With Kafka: ~500,000 events/second

---

## Next Steps

1. ✅ Backend API deployed
2. ✅ Dashboard pages created
3. ✅ Agent source code added
4. ⬜ Test end-to-end integration
5. ⬜ Deploy to production
6. ⬜ Configure alerts and automation
