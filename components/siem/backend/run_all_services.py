"""Start all development services concurrently (convenience wrapper).

This imports the existing `run_services` developer runner and extends its
`SERVICES` map with all microservices in this repository (excluding the agent).

Usage:
  python run_all_services.py
  python run_all_services.py --no-reload

Notes:
- Ports are chosen to avoid collisions with the default `run_services` set.
"""

from __future__ import annotations
import asyncio
import os
import run_services
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Add our services (if they do not already exist in run_services.SERVICES)
extra_services = {
    "psa": {"path": ROOT / "core-services" / "psa", "port": 8001, "env": {}},
    "siem": {"path": ROOT / "core-services" / "siem", "port": 8002, "env": {}},
    "edr": {"path": ROOT / "core-services" / "edr", "port": 8003, "env": {}},
    "vulnerability": {"path": ROOT / "core-services" / "vulnerability", "port": 8004, "env": {}},
    "auditing": {"path": ROOT / "core-services" / "auditing", "port": 8010, "env": {}},
    "rmm": {"path": ROOT / "core-services" / "rmm", "port": 8020, "env": {}},
    "detection": {"path": ROOT / "core-services" / "detection", "port": 8030, "env": {}},
    "compliance": {"path": ROOT / "core-services" / "compliance", "port": 8031, "env": {}},
}

# Merge extras into the existing SERVICES map without overwriting
for name, cfg in extra_services.items():
    if name not in run_services.SERVICES:
        run_services.SERVICES[name] = cfg

# For development convenience, bind PSA to all interfaces unless explicitly overridden
if os.environ.get("PSA_HOST") is None:
    os.environ["PSA_HOST"] = "0.0.0.0"


def main():
    # Default to running all known services in run_services.SERVICES
    services = list(run_services.SERVICES.keys())
    # Keep existing CLI behaviour for reload flag
    try:
        asyncio.run(run_services.main_async(services, True))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
