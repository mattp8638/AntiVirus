#!/usr/bin/env bash
# Consistent Fenrir platform backup (CORE-09): PostgreSQL (custom-format dump), the artifacts volume (evidence,
# forensic and support bundles) and offline-signed release manifests, with a manifest of SHA-256 hashes.
#
#   deploy/backup.sh [output directory]          default: /var/backups/fenrir
#
# Options (deploy/.env or the environment):
#   FENRIR_BACKUP_PASSPHRASE (or FENRIR_BACKUP_PASSPHRASE_FILE)  encrypt the backup: one fenrir-backup-<time>.tar.enc
#       file (AES-256, key from the passphrase with PBKDF2, 600,000 rounds) instead of a folder. install.sh sets one.
#       Keep the passphrase offline with .env: restore.sh needs it.
#   FENRIR_BACKUP_KEEP_DAYS   delete this script's backups older than this many days (default 14; 0 keeps all)
#   FENRIR_BACKUP_RCLONE_REMOTE   copy each backup off the server with rclone, e.g. "b2:my-bucket/fenrir"
#       (configure the remote with "rclone config" first). Only encrypted backups are copied off the server.
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
# Exact value (a passphrase may contain spaces): only surrounding quotes and a Windows line end are removed.
rawval() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | tail -1 | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"; }
setting() { local v="${!1:-}"; [ -n "$v" ] || v="$(rawval "$1")"; printf '%s' "$v"; }
passphrase="$(setting FENRIR_BACKUP_PASSPHRASE)"
passfile="$(setting FENRIR_BACKUP_PASSPHRASE_FILE)"
if [ -z "$passphrase" ] && [ -n "$passfile" ]; then passphrase="$(cat "$passfile")"; fi
result="$dir"
if [ -n "$passphrase" ]; then
  echo "Encrypting..."
  # The manifest inside still carries every file's SHA-256, so restore.sh detects any change after decrypting.
  tar -C "$OUT_ROOT" -cf - "$(basename "$dir")" |
    FENRIR_BACKUP_KEY="$passphrase" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:FENRIR_BACKUP_KEY \
      -out "$dir.tar.enc"
  rm -rf "$dir"
  result="$dir.tar.enc"
  printf '%s  %s\n' "$(sha256sum "$result" | cut -d' ' -f1)" "$(basename "$result")" > "$result.sha256"
else
  echo "WARNING: this backup is not encrypted. Set FENRIR_BACKUP_PASSPHRASE in deploy/.env to encrypt backups." >&2
fi

keep_days="$(setting FENRIR_BACKUP_KEEP_DAYS)"; keep_days="${keep_days:-14}"
if [ "$keep_days" -gt 0 ] 2>/dev/null; then
  find "$OUT_ROOT" -maxdepth 1 -name 'fenrir-backup-*' -mtime +"$keep_days" -print0 2>/dev/null |
    while IFS= read -r -d '' old; do rm -rf "$old"; echo "Removed a backup older than $keep_days days: $(basename "$old")"; done
fi

remote="$(setting FENRIR_BACKUP_RCLONE_REMOTE)"
if [ -n "$remote" ]; then
  if [ -z "$passphrase" ]; then
    echo "Not copying off the server: only encrypted backups leave it (set FENRIR_BACKUP_PASSPHRASE)." >&2
    exit 1
  fi
  command -v rclone >/dev/null || { echo "FENRIR_BACKUP_RCLONE_REMOTE is set but rclone is not installed" >&2; exit 1; }
  rclone copy "$result" "$remote" && rclone copy "$result.sha256" "$remote"
  echo "Copied off the server to $remote"
fi

echo "Backup written to $result"
echo "Remember: deploy/.env and deploy/signing are NOT in the backup. Keep them offline; FENRIR_VAULT_KEY is needed to read restored secrets."
