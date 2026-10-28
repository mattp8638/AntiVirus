#!/usr/bin/env bash
# Keep this server on the latest Fenrir code: when the deploy branch has new commits, pull them, rebuild the
# image (the old containers keep serving while it builds), restart, and check health. If the new build fails
# or is unhealthy, go back to the previous commit and rebuild that.
#
# Agents then upgrade themselves: each build carries a source fingerprint and devices replace themselves when
# the server's differs (Windows within about 30 minutes, Linux/macOS likewise).
#
# Settings (environment, or deploy/auto-update.env next to this script):
#   FENRIR_DEPLOY_BRANCH   branch to follow (default: main)
#   FENRIR_COMPOSE_FILES   compose files (default: docker-compose.yml, plus docker-compose.https.yml if present)
#   FENRIR_ENV_FILE        env file (default: deploy/.env)
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
[ -f "$DEPLOY_DIR/auto-update.env" ] && . "$DEPLOY_DIR/auto-update.env"
BRANCH="${FENRIR_DEPLOY_BRANCH:-main}"
ENV_FILE="${FENRIR_ENV_FILE:-$DEPLOY_DIR/.env}"
LOG_FILE="${FENRIR_UPDATE_LOG:-/var/log/fenrir-auto-update.log}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE" >&2; }

compose_args=(-f "$DEPLOY_DIR/docker-compose.yml")
if [ -n "${FENRIR_COMPOSE_FILES:-}" ]; then
  compose_args=()
  for f in $FENRIR_COMPOSE_FILES; do compose_args+=(-f "$f"); done
elif [ -f "$DEPLOY_DIR/docker-compose.https.yml" ]; then
  compose_args+=(-f "$DEPLOY_DIR/docker-compose.https.yml")
fi
compose() { docker compose "${compose_args[@]}" --env-file "$ENV_FILE" "$@"; }

healthy() {
  for _ in $(seq 60); do
    if compose exec -T cloud python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/ready", timeout=5)' >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  return 1
}

# Build profile: FENRIR_BUILD_PROFILE in the env file. production requires deploy/signing/codesign.pfx; lab builds
# unsigned agents. When it is not set, a server with a certificate builds production and one without builds lab
# (and says so every run), so an existing unsigned test server keeps updating.
build_profile() {
  local profile
  profile="$(sed -n 's/^FENRIR_BUILD_PROFILE=//p' "$ENV_FILE" 2>/dev/null | tail -1 | tr -d '"'"'"' \r')"
  if [ -z "$profile" ]; then
    if [ -s "$DEPLOY_DIR/signing/codesign.pfx" ]; then profile=production; else
      profile=lab
      log "WARNING: no code-signing certificate and FENRIR_BUILD_PROFILE is not set: building UNSIGNED lab agents." \
          "Set FENRIR_BUILD_PROFILE=production in $ENV_FILE once deploy/signing/codesign.pfx is in place."
    fi
  fi
  echo "$profile"
}

# Linux/macOS agent release signing key (FIX-07/AGT-03). Created on first run, kept only on this server under
# deploy/signing (never committed). To sign elsewhere instead, set FENRIR_RELEASE_KEY to an empty file, put the
# offline key's public key in FENRIR_RELEASE_PUBLIC_KEYS and copy signed manifests into deploy/releases.
release_key() {
  local key="${FENRIR_RELEASE_KEY:-$(sed -n 's/^FENRIR_RELEASE_KEY=//p' "$ENV_FILE" 2>/dev/null | tail -1 | tr -d '"'"'"' \r')}"
  if [ -z "$key" ]; then
    key="$DEPLOY_DIR/signing/release-ed25519.pem"
    if [ ! -s "$key" ]; then
      mkdir -p "$DEPLOY_DIR/signing"
      if (umask 077; openssl genpkey -algorithm ed25519 -out "$key") 2>/dev/null; then
        log "Created the agent release signing key $key. Back it up offline: agents built from now on only accept" \
            "updates signed with it. Public key: $(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | tail -c 32 | base64)"
      else
        log "WARNING: could not create a release signing key (is openssl installed?); agent releases stay unsigned."
        return 0
      fi
    fi
  fi
  export FENRIR_RELEASE_KEY="$key"
  # Release number: the git time of the last agent change, so rebuilding the same code is not a new release.
  FENRIR_RELEASE_SEQ="$(git_ log -1 --format=%ct -- agent/linux 2>/dev/null || true)"
  export FENRIR_RELEASE_SEQ
}

deploy() {  # build first so the running server keeps serving during the (slow) image build
  local profile
  profile="$(build_profile)"
  release_key
  case "$profile" in
    production)
      if [ ! -s "$DEPLOY_DIR/signing/codesign.pfx" ]; then
        log "ERROR: FENRIR_BUILD_PROFILE=production but deploy/signing/codesign.pfx is missing or empty; not building." \
            "Add the certificate, or set FENRIR_BUILD_PROFILE=lab for a test server. See docs/CODE_SIGNING.md."
        return 1
      fi
      [ -f "$DEPLOY_DIR/signing/codesign.password" ] || (umask 077; : > "$DEPLOY_DIR/signing/codesign.password")
      FENRIR_BUILD_PROFILE=production compose build && compose up -d && healthy ;;
    lab)
      # The lab override swaps the signing secrets for an empty placeholder, so every compose command needs it.
      case " ${compose_args[*]} " in *docker-compose.lab.yml*) ;; *) compose_args+=(-f "$DEPLOY_DIR/docker-compose.lab.yml") ;; esac
      FENRIR_BUILD_PROFILE=lab compose build && compose up -d && healthy ;;
    *) log "ERROR: FENRIR_BUILD_PROFILE must be production or lab (got '$profile')"; return 1 ;;
  esac
}

# Run git as the repository's owner: that account has the GitHub credentials and keeps file ownership intact.
REPO_OWNER="$(stat -c %U "$REPO_DIR")"
git_() {
  if [ "$(id -u)" -eq 0 ] && [ "$REPO_OWNER" != "root" ]; then sudo -u "$REPO_OWNER" -H git -C "$REPO_DIR" "$@"; else git -C "$REPO_DIR" "$@"; fi
}

exec 9>/tmp/fenrir-auto-update.lock
flock -n 9 || exit 0  # a previous run is still building

cd "$REPO_DIR"
git_ fetch --quiet origin "$BRANCH"
current="$(git_ rev-parse HEAD)"
target="$(git_ rev-parse "origin/$BRANCH")"
[ "$current" = "$target" ] && [ "${1:-}" != "--force" ] && exit 0

FAILED_FILE="${FENRIR_FAILED_FILE:-/var/tmp/fenrir-auto-update.failed}"
if [ "${1:-}" != "--force" ] && [ "$(cat "$FAILED_FILE" 2>/dev/null)" = "$target" ]; then
  exit 0  # this commit already failed; wait for a newer one (or run with --force)
fi

if ! git_ diff --quiet || ! git_ diff --cached --quiet; then
  log "Not updating: tracked files were changed by hand on this server (git status shows them). Commit or discard them first."
  exit 1
fi

log "Updating $BRANCH ${current:0:8} -> ${target:0:8}"
git_ checkout --quiet -B "$BRANCH" "$target"
if deploy; then
  log "Deployed ${target:0:8}: $(git_ log -1 --format=%s)"
  rm -f "$FAILED_FILE"
  docker image prune -f >/dev/null 2>&1 || true
  exit 0
fi

log "Build or health check failed for ${target:0:8}; rolling back to ${current:0:8}"
echo "$target" > "$FAILED_FILE"
git_ checkout --quiet -B "$BRANCH" "$current"
if deploy; then
  log "Rolled back to ${current:0:8}"
else
  log "ROLLBACK FAILED: check 'docker compose ps' and 'docker compose logs cloud'"
fi
exit 1
