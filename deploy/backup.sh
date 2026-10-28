#!/usr/bin/env bash
# Consistent Fenrir platform backup (CORE-09): PostgreSQL (custom-format dump), the artifacts volume (evidence,
# forensic and support bundles) and offline-signed release manifests, with a manifest of SHA-256 hashes.
#
#   deploy/backup.sh [output directory]          default: /var/backups/fenrir
#
# Not included, on purpose: deploy/.env (database password, FENRIR_SECRET_KEY, FENRIR_VAULT_KEY) and deploy/signing
# (code-signing certificate, release key). Keep those in an offline password manager or safe: without the same
# FENRIR_VAULT_KEY a restored database's stored secrets cannot be decrypted. The manifest records a fingerprint of the
# vault key so restore.sh can tell you whether you have the right one - never the key itself.
set -euo pipefail
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$DEPLOY_DIR")"
ENV_FILE="${FENRIR_ENV_FILE:-$DEPLOY_DIR/.env}"
OUT_ROOT="${1:-/var/backups/fenrir}"
compose_args=(-f "$DEPLOY_DIR/docker-compose.yml")
for f in ${FENRIR_COMPOSE_FILES:-}; do compose_args+=(-f "$f"); done
compose() { docker compose "${compose_args[@]}" --env-file "$ENV_FILE" "$@"; }
envval() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1 | tr -d '"'"'"' \r'; }

umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dir="$OUT_ROOT/fenrir-backup-$stamp"
mkdir -p "$dir"

echo "Dumping PostgreSQL..."
compose exec -T db pg_dump -U fenrir -Fc fenrir > "$dir/db.dump"
echo "Archiving the artifacts volume..."
compose exec -T cloud tar -C /data -czf - . > "$dir/artifacts.tar.gz"
if [ -d "$DEPLOY_DIR/releases" ] && [ -n "$(ls -A "$DEPLOY_DIR/releases" 2>/dev/null)" ]; then
  tar -C "$DEPLOY_DIR" -czf "$dir/releases.tar.gz" releases
fi

schema="$(compose exec -T db psql -U fenrir -d fenrir -tAc 'SELECT MAX(version) FROM schema_migrations' | tr -d '[:space:]')"
vault_fp=""
if [ -n "$(envval FENRIR_VAULT_KEY)" ]; then vault_fp="$(printf '%s' "$(envval FENRIR_VAULT_KEY)" | sha256sum | cut -c1-16)"; fi
commit="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
{
  printf '{\n  "format": "fenrir-backup/1",\n  "createdAt": "%s",\n  "commit": "%s",\n  "schemaVersion": %s,\n  "vaultKeyFingerprint": "%s",\n  "files": {\n' \
    "$stamp" "$commit" "${schema:-null}" "$vault_fp"
  first=1
  for f in "$dir"/*; do
    name="$(basename "$f")"; [ "$name" = manifest.json ] && continue
    [ $first -eq 1 ] || printf ',\n'
    printf '    "%s": {"sha256": "%s", "bytes": %s}' "$name" "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c %s "$f")"
    first=0
  done
  printf '\n  }\n}\n'
} > "$dir/manifest.json"
echo "Backup written to $dir"
echo "Remember: deploy/.env and deploy/signing are NOT in the backup. Keep them offline; FENRIR_VAULT_KEY is needed to read restored secrets."
