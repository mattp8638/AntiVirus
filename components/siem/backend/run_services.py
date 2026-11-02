"""Developer runner to start multiple FastAPI services concurrently.

Usage:
  python run_services.py            # starts identity, transport, ingestion, patch
  python run_services.py --services identity ingestion
  python run_services.py --no-reload

Behavior:
- Detects per-service venv at `<service>/.venv` and uses its Python if present, otherwise uses the current interpreter.
- Spawns each service with `python -m uvicorn app.main:app --host 0.0.0.0 --port <port> [--reload]`.
- Sets minimal default environment variables for each service. Override by exporting env vars yourself before running.
- Streams subprocess stdout/stderr with a service name prefix and performs a simple TCP health check after start.
- Gracefully terminates all children on CTRL+C.

Note: This script is for development convenience only.
"""

from __future__ import annotations
import argparse
import asyncio
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parent

SERVICES: Dict[str, Dict] = {
    "api": {
        "path": ROOT,
        "port": 8080,
        "module": "api:app",
        "env": {},
    },
    "identity": {
        "path": ROOT / "core-services" / "identity",
        "port": 8085,
        "env": {
            "IDENTITY_HMAC_SHARED_KEY": "replace-me",
            "IDENTITY_SIGNATURE_TTL": "120",
        },
    },
    "transport": {
        "path": ROOT / "transport",
        "port": 8081,
        "env": {
            "TRANSPORT_IDENTITY_URL": "http://localhost:8085",
            "TRANSPORT_PENETRATION_URL": "http://localhost:8083",
            "TRANSPORT_TRUSTED_FINGERPRINTS": "sha256:examplefingerprint",
        },
    },
    "ingestion": {
        "path": ROOT / "ingestion",
        "port": 8000,
        "env": {},
    },
    "patch": {
        "path": ROOT / "core-services" / "patch",
        "port": 8082,
        "env": {
            "PATCH_API_KEY": "devkey",
        },
    },
    "penetration": {
        "path": ROOT / "core-services" / "penetration",
        "port": 8083,
        "env": {
            "PENETRATION_API_KEY": "devkey",
        },
    },
}

# Allow per-service port overrides via environment variables (e.g., IDENTITY_PORT=8085)
for _name, _cfg in SERVICES.items():
    env_port = os.environ.get(f"{_name.upper()}_PORT")
    if env_port:
        try:
            _cfg["port"] = int(env_port)
        except ValueError:
            pass

# Ensure transport points at the active identity port unless explicitly set
if "transport" in SERVICES and "identity" in SERVICES:
    identity_port = SERVICES["identity"]["port"]
    SERVICES["transport"]["env"].setdefault(
        "TRANSPORT_IDENTITY_URL", f"http://localhost:{identity_port}"
    )


def _parse_env_file(path: Path) -> Dict[str, str]:
    """Read a simple KEY=VALUE .env file and return a dict.

    Supports quoted values and ignores comments/blank lines.
    """
    result: Dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return result
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        result[k] = v
    return result

# Load a root .env if present (lowest precedence)
ROOT_ENV = _parse_env_file(ROOT / ".env")
if ROOT_ENV:
    print(f"Loaded root .env ({len(ROOT_ENV)} keys)")



async def read_stream(stream: asyncio.StreamReader, prefix: str) -> None:
    while True:
        line = await stream.readline()
        if not line:
            break
        print(f"[{prefix}] {line.decode().rstrip()}")


async def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            await asyncio.sleep(0.2)
    return False


def find_venv_python(service_path: Path) -> Optional[str]:
    # Prefer .venv in service directory
    venv_dir = service_path / ".venv"
    if sys.platform == "win32":
        candidate = venv_dir / "Scripts" / "python.exe"
    else:
        candidate = venv_dir / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    return None


async def run_service(name: str, cfg: Dict, reload: bool) -> asyncio.subprocess.Process:
    service_path: Path = cfg["path"]
    port: int = cfg["port"]
    module: str = cfg.get("module", "app.main:app")
    env: Dict[str, str] = os.environ.copy()

    # Apply root .env defaults (lowest precedence)
    for k, v in ROOT_ENV.items():
        env.setdefault(k, v)

    # Apply per-service .env (overrides root .env but not environment variables)
    service_env = _parse_env_file(service_path / ".env")
    if service_env:
        for k, v in service_env.items():
            env.setdefault(k, v)

    # Add default envs if not explicitly set in any env or .env files
    for k, v in cfg.get("env", {}).items():
        env.setdefault(k, v)

    # Ensure subprocesses can import repo-level packages by adding project root to PYTHONPATH
    root_path = str(ROOT)
    existing_pp = env.get("PYTHONPATH")
    if existing_pp:
        env["PYTHONPATH"] = root_path + os.pathsep + existing_pp
    else:
        env["PYTHONPATH"] = root_path

    python_exe = find_venv_python(service_path) or sys.executable

    host = os.environ.get(f"{name.upper()}_HOST", "127.0.0.1")
    cmd = [python_exe, "-m", "uvicorn", module, "--host", host, "--port", str(port)]
    if reload:
        cmd.append("--reload")

    print(f"Starting {name} on port {port} (cwd={service_path}) using {python_exe}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(service_path),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Stream stdout/stderr
    asyncio.create_task(read_stream(process.stdout, name))
    asyncio.create_task(read_stream(process.stderr, name + "-err"))

    # Wait for health
    ok = await wait_for_port("127.0.0.1", port, timeout=12.0)
    if ok:
        print(f"{name} is up on port {port}")
    else:
        print(f"WARNING: {name} did not respond on port {port} within timeout")

    return process


async def main_async(services: list[str], reload: bool) -> int:
    procs: dict[str, asyncio.subprocess.Process] = {}

    exit_code = 0
    try:
        for name in services:
            if name not in SERVICES:
                print(f"Unknown service: {name}")
                exit_code = 2
                return exit_code
            proc = await run_service(name, SERVICES[name], reload)
            procs[name] = proc

        # Monitor processes
        while True:
            await asyncio.sleep(0.5)
            for name, proc in list(procs.items()):
                if proc.returncode is None:
                    # poll
                    rc = proc.returncode
                    if rc is None:
                        continue
                # Process ended
                rc = await proc.wait()
                print(f"{name} exited with {rc}, shutting other services down")
                raise RuntimeError(f"{name} exited: {rc}")
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print("Error:", exc)
    finally:
        # Terminate children
        print("Shutting down services...")
        for name, proc in procs.items():
            if proc.returncode is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        # Give them a moment
        await asyncio.sleep(1)
        for name, proc in procs.items():
            if proc.returncode is None:
                try:
                    proc.kill()
                except Exception:
                    pass
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Run multiple services for local development")
    parser.add_argument(
        "--services",
        "-s",
        nargs="+",
        default=["identity", "transport", "ingestion", "penetration"],
        help="Services to run",
    )
    parser.add_argument("--no-reload", action="store_true", help="Disable uvicorn --reload")
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args.services, not args.no_reload))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
