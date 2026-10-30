#!/usr/bin/env bash
# Restore a Fenrir platform backup made by backup.sh (CORE-09, AT-24).
#
#   deploy/restore.sh <backup directory> [--yes] [--allow-different-vault-key]
#
# Checks every file against the manifest and the vault key fingerprint against deploy/.env, stops the API, replaces
# the database and the artifacts volume, starts the API, waits for /ready, then checks that the audit chain verifies
# and every stored secret still decrypts. Completed commands are not re-run: they are restored as completed.
set -euo pipefail
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${FENRIR_ENV_FILE:-$DEPLOY_DIR/.env}"
dir="${1:?usage: restore.sh <backup directory> [--yes] [--allow-different-vault-key]}"
shift
yes=0; allow_key=0
for arg in "$@"; do case "$arg" in --yes) yes=1 ;; --allow-different-vault-key) allow_key=1 ;; *) echo "unknown option $arg"; exit 2 ;; esac; done
compose_args=(-f "$DEPLOY_DIR/docker-compose.yml")
for f in ${FENRIR_COMPOSE_FILES:-}; do compose_args+=(-f "$f"); done
compose() { docker compose "${compose_args[@]}" --env-file "$ENV_FILE" "$@"; }
envval() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1 | tr -d '"'"'"' \r'; }
manifest="$dir/manifest.json"
[ -f "$manifest" ] || { echo "No manifest.json in $dir"; exit 1; }
grep -q '"format": "fenrir-backup/1"' "$manifest" || { echo "Not a Fenrir backup"; exit 1; }

echo "Checking files against the manifest..."
python3 - "$dir" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]); manifest = json.loads((root / "manifest.json").read_text())
for name, meta in manifest["files"].items():
    data = (root / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != meta["sha256"] or len(data) != meta["bytes"]:
        sys.exit(f"{name} does not match the manifest: the backup is damaged or was altered")
print(f"OK: {len(manifest['files'])} files, schema {manifest['schemaVersion']}, made {manifest['createdAt']}")
PY
want="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vaultKeyFingerprint"])' "$manifest")"
have=""; if [ -n "$(envval FENRIR_VAULT_KEY)" ]; then have="$(printf '%s' "$(envval FENRIR_VAULT_KEY)" | sha256sum | cut -c1-16)"; fi
if [ -n "$want" ] && [ "$want" != "$have" ] && [ $allow_key -eq 0 ]; then
  echo "FENRIR_VAULT_KEY in $ENV_FILE is not the key this backup was made with: restored secrets would not decrypt."
  echo "Put the original key back (or pass --allow-different-vault-key if you rotated it and kept the old one in FENRIR_VAULT_OLD_KEYS)."
  exit 1
fi
if [ $yes -eq 0 ]; then
  read -r -p "This REPLACES the current database and artifacts with the backup. Type RESTORE to continue: " answer
  [ "$answer" = RESTORE ] || { echo "Cancelled"; exit 1; }
fi

echo "Stopping the API and the background worker..."
compose stop worker cloud
echo "Restoring PostgreSQL..."
compose exec -T db psql -U fenrir -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS fenrir WITH (FORCE)" -c "CREATE DATABASE fenrir OWNER fenrir"
compose exec -T db pg_restore -U fenrir -d fenrir --no-owner --exit-on-error < "$dir/db.dump"
echo "Restoring artifacts..."
compose start cloud
compose exec -T cloud sh -c 'find /data -mindepth 1 -delete && tar -C /data -xzf -' < "$dir/artifacts.tar.gz"
if [ -f "$dir/releases.tar.gz" ]; then tar -C "$DEPLOY_DIR" -xzf "$dir/releases.tar.gz"; fi
compose restart cloud
for i in $(seq 1 60); do
  if compose exec -T cloud python -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8080/ready", timeout=3).status == 200 else 1)' 2>/dev/null; then break; fi
  sleep 3
done
compose start worker  # only once the restored database and artifacts are in place
echo "Verifying the restored platform..."
compose exec -T cloud python - <<'PY'
import sys
from fenrir_cloud import audit, crypto
from fenrir_cloud.config import get_settings
from fenrir_cloud.db import init_engine, session_factory
init_engine(get_settings().database_url)
db = session_factory()()
chain = audit.verify_chain(db)
vault = crypto.verify_all(db)
print(f"audit chain: {'intact' if chain['valid'] else 'BROKEN'} ({chain['checked']} entries); "
      f"secrets: {vault['checked']} checked, {vault['failed']} could not be decrypted")
sys.exit(0 if vault["failed"] == 0 and (chain["valid"] or not chain.get("tampered")) else 1)
PY
echo "Restore complete."
