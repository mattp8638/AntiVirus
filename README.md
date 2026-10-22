# Fenrir Platform

One product that combines endpoint protection (AV, EDR, ransomware, DNS and web protection), a SIEM/XDR, exposure management (vulnerabilities, attack surface, compliance), an RMM (monitoring, scripting, automation, patching, software deployment and browser-based remote control) and an MSP business suite (a ConnectWise-style PSA, CRM, agreements and billing, and a client portal). Five earlier codebases are folded into it:

| Source repo | Lives in | Role now |
|---|---|---|
| `mattp8638/AntiVirus` | `agent/`, `backend/`, `schema/` | Windows/Linux/macOS endpoint agents (the protection engine) |
| `Palmertech-Webdev/Sentinel` | `components/sentinel/` | Investigation tooling; its playbooks drive Fenrir incidents |
| `Palmertech-Webdev/SIEM-Work-Dev` | `components/siem/` | SIEM/RMM/PSA microservices and agent, kept as reference and for migration |
| `zy538324/Palmertech-CRM` | `components/crm/` | CRM screens, rebuilt as the console's CRM module |
| `zy538324/signaturedb-fenrir` | `components/signaturedb/` | Cloudflare edge threat feed, consumed by Fenrir Cloud |

New in this repo:

- **`cloud/`: Fenrir Cloud.** One FastAPI service that runs the agent control plane, SIEM, detection, response, DNS filtering, intel, exposure management, compliance, RMM, the remote-access relay, PSA, CRM and billing. It implements the API contract the Windows agent already speaks.
- **`console/`: Fenrir Console.** A React web app for all of the above, served by Fenrir Cloud.
- **`agent/linux/cmd/fenrir-agent`.** A fully managed Linux agent: static Go binary, no kernel modules. Includes remote desktop (X11), terminal and file transfer.
- **`agent/windows/tools/remotehelper`: `fenrir-remote.exe`.** The Windows remote-control helper the service starts in the signed-in user's session.
- **`deploy/`, `packaging/`, `Makefile`.** One Docker image, docker-compose with PostgreSQL, Linux packages and CI.

## Quick start (local)

```bash
make console agents                      # build the UI and Linux agents
cd cloud && pip install -r requirements.txt
FENRIR_ADMIN_PASSWORD='choose-a-long-one' FENRIR_PUBLIC_URL=http://localhost:8080 \
  python3 -m uvicorn --factory fenrir_cloud.main:create_app --port 8080
# optional: demo data (3 customers, 15 devices, a replayed ransomware attack, patches, scripts, tickets, time, quotes)
python3 -m fenrir_cloud.demo --password 'choose-a-long-one'
```

Open http://localhost:8080 and sign in as `admin@fenrir.local`.

## Production

```bash
cp deploy/.env.example deploy/.env       # set real secrets
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

Put it behind TLS (Caddy, nginx, Cloudflare Tunnel). Agents and DoH need HTTPS.

## Deploying agents

1. In the console, open **Deploy agents** and create an enrollment token for a customer.
2. Install the agent:
   - **Linux:** `curl -fsSL https://<server>/install/linux.sh | sudo FENRIR_SERVER=https://<server> FENRIR_TOKEN=<token> sh`, or install the `.deb` from `dist/packages/`.
   - **Windows:** build `FenrirSetup.exe` (`agent/windows/installer`). Set `HKLM\SOFTWARE\FenrirAgent\ControlPlaneBaseUrl` to your server. Devices enrol into **Unassigned**; approve them and move them to the right customer from the Devices page.
   - **macOS:** the Swift agent in `agent/macos` (build on a Mac).

## Tests

```bash
cd cloud && python3 -m pytest -q             # 75 tests; set FENRIR_TEST_DATABASE_URL to run on PostgreSQL
cd ml && python3 -m pytest -q                # feature/model parity
make -C agent/linux test                     # Go unit tests (remote desktop tests use Xvfb when installed)
cd console && npm run build                  # type-check + bundle
```

## Machine learning

`ml/` holds the static malware model: training, evaluation and the cross-language feature extractor. Results are in [ml/README.md](ml/README.md).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the pieces fit together
- [docs/COMPETITIVE_ANALYSIS.md](docs/COMPETITIVE_ANALYSIS.md): feature map against Heimdal, ESET, ConnectSecure, RoboShadow, SentinelOne and Defender
- [docs/RMM_PSA.md](docs/RMM_PSA.md): RMM, remote access and PSA: what they do and how to set up email
- [docs/REMOTE_PROTOCOL.md](docs/REMOTE_PROTOCOL.md): the remote-access wire protocol
- [docs/ROADMAP.md](docs/ROADMAP.md): what is built, what is next
- [docs/DRIVER_SIGNING.md](docs/DRIVER_SIGNING.md): what Windows/Apple signing really costs
- [components/README.md](components/README.md): where the vendored code came from and what was removed
