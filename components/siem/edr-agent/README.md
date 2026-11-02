# TamsilCMS Sentinel EDR Agent

Enterprise EDR agent that reports to TamsilCMS SIEM platform.

## Features

- Real-time telemetry collection
- Process monitoring
- File operations tracking
- Network connection monitoring
- Integration with SIEM backend
- Remote command execution

## Building

```powershell
# Build agent
cargo build --release

# Output: target/release/sentinel-agent.exe
```

## Configuration

1. Copy config example:
```powershell
cp config.example.json config.json
```

2. Edit `config.json`:
```json
{
  "siem_endpoint": "https://siem.yourdomain.com",
  "api_key": "your-api-key",
  "reporting_interval_secs": 10
}
```

## Running

```powershell
# Run directly
./target/release/sentinel-agent.exe

# Install as Windows service
sc.exe create TamsilCMSSentinel binPath= "C:\\Path\\To\\sentinel-agent.exe"
sc.exe start TamsilCMSSentinel
```

## Integration with SIEM

The agent automatically:
1. Registers with SIEM backend on startup
2. Sends telemetry events every 10 seconds
3. Polls for commands from SIEM
4. Reports threat detections

## Architecture

```
Endpoint (Windows)
  └── Sentinel Agent
      ├── ETW Monitor
      ├── Process Monitor
      ├── File Monitor
      ├── Network Monitor
      └── API Client
           |
           v
      SIEM Backend
      └── /api/v1/edr/*
           ├── /agents/register
           ├── /events
           ├── /threats
           └── /commands
                |
                v
           SIEM Dashboard
           └── /edr/*
               ├── Dashboard
               ├── Agents
               ├── Threats
               └── Events
```
