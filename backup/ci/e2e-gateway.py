"""NAS gateway end to end: a real Fenrir Cloud server and two real backup agents on one Linux machine.

The "laptop" (its own /etc/machine-id in a private mount namespace, so it is a different machine) backs up into a
repository only the "gateway" can reach: first through the server relay, then directly. Needs root (unshare/mount).

    sudo python3 backup/ci/e2e-gateway.py <work dir> <path to fenrir-backup-agent> <path to cloud/>

with the platform's Python requirements installed (cloud/requirements.txt) plus httpx and cryptography."""

import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

W = Path(sys.argv[1])
AGENT = sys.argv[2]
CLOUD = Path(sys.argv[3])
shutil.rmtree(W, ignore_errors=True)
W.mkdir(parents=True)
PORT = 18080
BASE = f"http://127.0.0.1:{PORT}"
env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
procs = []


def b64(b):
    return base64.b64encode(b).decode()


def seal(pk_b64, plaintext: bytes):
    """Browser side of protocol::seal (fenrir-agent-seal-v1)."""
    apk = base64.b64decode(pk_b64)
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(apk))
    key = HKDF(SHA256(), 32, salt=epk + apk, info=b"fenrir-agent-seal-v1").derive(shared)
    nonce = os.urandom(12)
    return {"v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, None))}


def start_server():
    e = dict(env, FENRIR_DATABASE_URL=f"sqlite:///{W}/fenrir.db", FENRIR_ADMIN_PASSWORD="e2e-admin-password-123",
             FENRIR_SECRET_KEY="e2e-secret", FENRIR_PUBLIC_URL=BASE, FENRIR_REQUIRE_MFA="false",
             FENRIR_BACKUP_AGENTS_DIR=str(W / "builds"), FENRIR_DNS_BLOCKLISTS_ENABLED="false")
    log = open(W / "server.log", "w")
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "fenrir_cloud.main:create_app", "--port", str(PORT),
                          "--workers", "1"], cwd=CLOUD, env=e, stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(120):
        try:
            if httpx.get(f"{BASE}/ready", timeout=2).status_code < 500:
                return
        except httpx.HTTPError:
            time.sleep(0.5)
    raise SystemExit("server did not start: " + (W / "server.log").read_text()[-3000:])


def agent(name, *args, background=False):
    state = W / name
    state.mkdir(exist_ok=True)
    e = dict(env, FENRIR_AGENT_STATE=str(state))
    cmd = [AGENT, *args]
    if name == "laptop":
        # Another computer: its own /etc/machine-id, in a private mount namespace.
        mid = W / "laptop-machine-id"
        mid.write_text(uuid.uuid4().hex + "\n") if not mid.exists() else None
        cmd = ["unshare", "--mount", "sh", "-c", f'mount --bind "{mid}" /etc/machine-id && exec "$0" "$@"', *cmd]
    if background:
        log = open(W / f"{name}.log", "w")
        p = subprocess.Popen(cmd, env=e, stdout=log, stderr=subprocess.STDOUT)
        procs.append(p)
        return p
    r = subprocess.run(cmd, env=e, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (name, args, r.stdout, r.stderr)
    return r.stdout


def try_unlock(c, repo_id, machine, passphrase):
    """The console's unlock: password check, then the passphrase sealed to a machine that tries it on the repository."""
    rt = c.post("/api/console/auth/reauth", json={"password": "e2e-admin-password-123"}).json()["reauthToken"]
    sealed = seal(machine["publicKey"], json.dumps({"passphrase": passphrase, "recovery_key": None}).encode())
    r = c.post(f"/api/console/backup/repositories/{repo_id}/unlock", headers={"X-Fenrir-Reauth": rt},
               json={"agentId": machine["id"], "sealed": sealed})
    assert r.status_code == 200, r.text
    for _ in range(120):
        out = c.get(f"/api/console/backup/unlock/{r.json()['id']}").json()
        if out["state"] != "pending":
            print(f"  unlock with {'the right' if passphrase.startswith('e2e') else 'a wrong'} passphrase: {out['state']}")
            return out
        time.sleep(1)
    raise SystemExit("the unlock check did not finish")


def wait_job(c, jid, what, seconds=300):
    for _ in range(seconds):
        j = c.get(f"/api/console/backup/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} {j.get('error') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j
        time.sleep(1)
    raise SystemExit(f"{what} did not finish")


try:
    start_server()
    c = httpx.Client(base_url=BASE, timeout=60)
    tok = c.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": "e2e-admin-password-123"}).json()["token"]
    c.headers["Authorization"] = f"Bearer {tok}"
    tenant = c.post("/api/console/tenants", json={"name": "E2E Ltd", "template": "balanced"}).json()["id"]
    link = c.post("/api/console/backup/enrollments", json={"tenantId": tenant, "role": "server"}).json()["token"]

    agent("gateway", "enroll", "--server", f"{BASE}/backup", f"--token={link}", "--role", "server")
    agent("laptop", "enroll", "--server", f"{BASE}/backup", f"--token={link}", "--role", "workstation")
    agent("gateway", "run", background=True)
    agent("laptop", "run", background=True)
    for _ in range(60):
        machines = {m["hostname"]: m for m in c.get("/api/console/backup/agents").json()}
        if len(machines) >= 2 and all("gateway" in m["capabilities"] for m in machines.values()):
            break
        time.sleep(1)
    ids = {json.loads((W / n / "agent.json").read_text())["agent_id"]: n for n in ("gateway", "laptop")}
    agents = {ids[m["id"]]: m for m in c.get("/api/console/backup/agents").json()}
    gw, laptop = agents["gateway"], agents["laptop"]
    print("agents online:", gw["online"], laptop["online"])

    # A repository only the gateway can reach (its folder is "the NAS").
    nas = W / "nas" / "repo"
    repo_uuid = str(uuid.uuid4())
    rk = {"format": "fenrir-recovery-key", "version": 1, "repo_id": repo_uuid, "slot_id": str(uuid.uuid4()), "key": b64(os.urandom(32))}
    secret = lambda first: json.dumps({"passphrase": "e2e repository passphrase", "recovery_key": json.dumps(rk) if first else None}).encode()
    r = c.post("/api/console/backup/repositories", json={"name": "NAS", "path": str(nas), "repoUuid": repo_uuid,
                                                         "initAgentId": gw["id"], "access": [{"agentId": gw["id"], "sealed": seal(gw["publicKey"], secret(True))}]})
    assert r.status_code == 200, r.text
    wait_job(c, r.json()["initJobId"], "create repository on the gateway")

    # Relay only first: the gateway does not listen.
    assert c.post(f"/api/console/backup/repositories/{r.json()['id']}/gateway", json={"agentId": gw["id"], "port": 0}).status_code == 200
    repo_id = r.json()["id"]
    assert c.post(f"/api/console/backup/repositories/{repo_id}/access", json={
        "agentId": laptop["id"], "sealed": seal(laptop["publicKey"], secret(False)), "viaGateway": True}).status_code == 200
    disk = W / "laptop-disk.img"
    disk.write_bytes(bytes((i * 31 + i // 4096) % 251 for i in range(24 << 20)))
    t = time.time()
    j = c.post(f"/api/console/backup/agents/{laptop['id']}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(disk)]}, "repositoryId": repo_id}).json()
    wait_job(c, j["id"], "laptop backup through the RELAY")
    print(f"  ({time.time() - t:.1f}s for 24 MiB)")
    assert any(p.name.startswith("chunks") for p in nas.iterdir()), "nothing written on the NAS"
    j = c.post(f"/api/console/backup/agents/{laptop['id']}/jobs", json={"kind": {"type": "verify", "level": "full"}, "repositoryId": repo_id}).json()
    wait_job(c, j["id"], "laptop full verify through the relay")
    # Images open only after an unlock: a fresh password check, then the passphrase tried on a real machine.
    assert c.get("/api/console/backup/images", params={"repositoryId": repo_id}).status_code == 403
    assert try_unlock(c, repo_id, gw, "not the passphrase")["state"] == "failed", "a wrong passphrase must not unlock"
    out = try_unlock(c, repo_id, gw, "e2e repository passphrase")
    assert out["state"] == "unlocked", out
    c.headers["X-Fenrir-Unlock"] = out["token"]
    images = c.get("/api/console/backup/images", params={"repositoryId": repo_id}).json()
    assert images, "no images listed after the unlock"
    print("  images:", [(i["hostname"], i["capturedBytes"]) for i in images])

    # Retention through the gateway is refused for the laptop (append-only); the gateway itself can.
    j = c.post(f"/api/console/backup/repositories/{repo_id}/prune", json={"dryRun": True}).json()
    wait_job(c, j["id"], "space-reclamation estimate (runs on the gateway)")

    # Now direct: the gateway listens; the laptop uses the address it reports.
    assert c.post(f"/api/console/backup/repositories/{repo_id}/gateway", json={"agentId": gw["id"], "port": 18475}).status_code == 200
    for _ in range(60):
        g = [x for x in c.get("/api/console/backup/repositories").json() if x["id"] == repo_id][0]["gateway"]
        if g["addresses"]:
            break
        time.sleep(1)
    print("  gateway addresses:", g["addresses"])
    disk.write_bytes(bytes((i * 17 + i // 999) % 249 for i in range(24 << 20)))
    t = time.time()
    j = c.post(f"/api/console/backup/agents/{laptop['id']}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(disk)]}, "repositoryId": repo_id}).json()
    wait_job(c, j["id"], "laptop backup DIRECT")
    print(f"  ({time.time() - t:.1f}s for 24 MiB)")
    log = (W / "laptop.log").read_text()
    print("  laptop log mentions direct address:", "18475" in log or "not reachable directly" not in log)

    # AT-19: restore the latest backup to a new disk file on the laptop (an isolated target, nothing else is
    # touched) and compare it with the source by SHA-256.
    images = c.get("/api/console/backup/images", params={"repositoryId": repo_id}).json()
    latest = max(images, key=lambda i: i["created"])
    rt = c.post("/api/console/auth/reauth", json={"password": "e2e-admin-password-123"}).json()["reauthToken"]
    restored = W / "restored-disk.img"
    r = c.post("/api/console/backup/restores", headers={"X-Fenrir-Reauth": rt}, json={
        "imageId": latest["imageId"], "agentId": laptop["id"],
        "target": {"type": "disk", "device": str(restored), "disk": 0, "confirm": str(restored), "grow": False}})
    assert r.status_code == 200, r.text
    t = time.time()
    wait_job(c, r.json()["id"], "restore the latest backup to a new disk file")
    source = disk.read_bytes()
    got = restored.read_bytes()[: len(source)]
    assert hashlib.sha256(got).hexdigest() == hashlib.sha256(source).hexdigest(), "the restored disk differs from the source"
    print(f"  restore verified by SHA-256 ({len(source) >> 20} MiB) in {time.time() - t:.1f}s")
    print("E2E OK")
finally:
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
