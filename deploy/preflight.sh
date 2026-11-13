#!/usr/bin/env bash
# Go-live check for a Fenrir server. Run it on the server, from the checkout, before customers depend on it and after
# every upgrade:
#
#   sudo deploy/preflight.sh                       full check: configuration, host, then the live server over HTTPS
#   deploy/preflight.sh --offline                  configuration and host only (before the first start)
#   deploy/preflight.sh --no-host --url https://…  configuration and the live server, without Docker/disk/backup checks
#   deploy/preflight.sh --url https://rmm.example.com --backup-dir /var/backups/fenrir --strict
#
# It reads deploy/.env as data (never sources or prints it) and only reports whether each secret is acceptable.
# Each line is PASS, WARN (a risk to decide on) or FAIL (fix before go-live). Exit status: 0 when nothing failed,
# 1 when something did, 2 for bad arguments. --strict also fails on warnings.
#
# Environment: FENRIR_ENV_FILE (default deploy/.env), FENRIR_COMPOSE_FILES (extra Compose files, as for backup.sh;
# deploy/docker-compose.https.yml is added automatically when present), FENRIR_BACKUP_DIR (default /var/backups/fenrir).
set -uo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$DEPLOY_DIR")"
ENV_FILE="${FENRIR_ENV_FILE:-$DEPLOY_DIR/.env}"
BACKUP_DIR="${FENRIR_BACKUP_DIR:-/var/backups/fenrir}"
URL_OVERRIDE=""
OFFLINE=0
NO_HOST=0
STRICT=0

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE=1 ;;
    --strict) STRICT=1 ;;
    --no-host) NO_HOST=1 ;;
    --url) URL_OVERRIDE="${2:-}"; shift ;;
    --url=*) URL_OVERRIDE="${1#*=}" ;;
    --env-file) ENV_FILE="${2:-}"; shift ;;
    --env-file=*) ENV_FILE="${1#*=}" ;;
    --backup-dir) BACKUP_DIR="${2:-}"; shift ;;
    --backup-dir=*) BACKUP_DIR="${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_PASS=$'\033[32m'; C_WARN=$'\033[33m'; C_FAIL=$'\033[31m'; C_HEAD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_PASS=""; C_WARN=""; C_FAIL=""; C_HEAD=""; C_OFF=""
fi
passes=0; warns=0; fails=0
pass() { passes=$((passes + 1)); printf '  %sPASS%s  %s\n' "$C_PASS" "$C_OFF" "$1"; }
warn() { warns=$((warns + 1)); printf '  %sWARN%s  %s\n' "$C_WARN" "$C_OFF" "$1"; }
fail() { fails=$((fails + 1)); printf '  %sFAIL%s  %s\n' "$C_FAIL" "$C_OFF" "$1"; }
note() { printf '  info  %s\n' "$1"; }
section() { printf '\n%s%s%s\n' "$C_HEAD" "$1" "$C_OFF"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Value of KEY in the env file, parsed the way Docker Compose reads it: last assignment wins, an unquoted value ends at
# " #", and surrounding quotes are removed. Nothing in the file is executed.
envval() {
  local line v
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?$1=" "$ENV_FILE" 2>/dev/null | tail -1)"
  [ -n "$line" ] || return 0
  v="${line#*=}"
  v="${v%$'\r'}"
  case "$v" in
    \"*) v="${v#\"}"; v="${v%%\"*}" ;;
    \'*) v="${v#\'}"; v="${v%%\'*}" ;;
    *) v="${v%%[[:space:]]#*}"; v="$(printf '%s' "$v" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')" ;;
  esac
  printf '%s' "$v"
}
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
# Same markers as cloud/fenrir_cloud/production.py.
placeholder() { case "$(lower "$1")" in *change-me*|*changeme*|*replace-me*|*replaceme*|*your-*) return 0 ;; esac; return 1; }
truthy() { case "$(lower "$1")" in 1|true|yes|on) return 0 ;; esac; return 1; }
# Permission bits for group or others (0 when the file is owner-only).
loose_perms() { local m; m="$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null)"; [ -n "$m" ] && [ "$(( 8#$m & 077 ))" -ne 0 ]; }
days_until() {  # days from now until an openssl "notAfter" date; empty if it cannot be parsed
  local end now
  end="$(date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$1" +%s 2>/dev/null)" || return 0
  now="$(date -u +%s)"
  [ -n "$end" ] && echo $(( (end - now) / 86400 ))
}

printf '%sFenrir go-live preflight%s  (%s)\n' "$C_HEAD" "$C_OFF" "$(date -u +%Y-%m-%dT%H:%MZ)"

# ---------------------------------------------------------------------------------------------------------------------
section "Configuration ($ENV_FILE)"
if [ ! -f "$ENV_FILE" ]; then
  fail "No env file. Copy deploy/.env.example to deploy/.env and fill it in (README, step 2)."
  printf '\nNot ready: the remaining checks need the env file.\n'
  exit 1
fi
if [ ! -r "$ENV_FILE" ]; then
  fail "Cannot read $ENV_FILE. Run with sudo, or as the account that owns it."
  printf '\nNot ready: the remaining checks need the env file.\n'
  exit 1
fi
if loose_perms "$ENV_FILE"; then
  fail ".env can be read by other accounts on this server. Run: chmod 600 $ENV_FILE"
else
  pass ".env is readable by its owner only"
fi

if have git && git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  tracked="$(git -C "$REPO_DIR" ls-files -- deploy/.env 'deploy/signing/*' deploy/auto-update.env | grep -v '^deploy/signing/README.md$')"
  if [ -n "$tracked" ]; then
    fail "Secrets are tracked by Git: $(echo "$tracked" | tr '\n' ' ')- remove them from the index (git rm --cached) and rotate them."
  else
    pass "No secrets are tracked by Git"
  fi
fi

# check_secret NAME MIN_LENGTH WHY
check_secret() {
  local v; v="$(envval "$1")"
  if [ -z "$v" ]; then fail "$1 is empty. $3"
  elif placeholder "$v"; then fail "$1 is still the template placeholder. $3"
  elif [ "${#v}" -lt "$2" ]; then fail "$1 is shorter than $2 characters. $3"
  else pass "$1 is set and long enough"
  fi
}
check_secret POSTGRES_PASSWORD 16 "Use: openssl rand -hex 32"
check_secret FENRIR_SECRET_KEY 32 "It signs console sessions. Use: openssl rand -hex 32"
check_secret FENRIR_ADMIN_PASSWORD 12 "It becomes the first administrator's password. Use: openssl rand -hex 24"

vault="$(envval FENRIR_VAULT_KEY)"
vault_file="$(envval FENRIR_VAULT_KEY_FILE)"
if [ -n "$vault" ]; then
  if placeholder "$vault"; then
    fail "FENRIR_VAULT_KEY is still a placeholder. Use: openssl rand -base64 32"
  elif [ "$(printf '%s' "$vault" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" = "32" ]; then
    pass "FENRIR_VAULT_KEY is base64 of 32 bytes"
  else
    fail "FENRIR_VAULT_KEY is not base64 of 32 bytes, so stored credentials cannot be encrypted. Use: openssl rand -base64 32"
  fi
elif [ -n "$vault_file" ]; then
  note "FENRIR_VAULT_KEY_FILE is used ($vault_file); check that file is mounted into the containers"
else
  fail "FENRIR_VAULT_KEY is empty. It encrypts stored credentials (Microsoft 365, SNMP, backup APIs). Use: openssl rand -base64 32"
fi

# The same value used twice means one leak exposes both.
dupes=""
names=(POSTGRES_PASSWORD FENRIR_SECRET_KEY FENRIR_VAULT_KEY FENRIR_ADMIN_PASSWORD)
for ((i = 0; i < ${#names[@]}; i++)); do
  for ((j = i + 1; j < ${#names[@]}; j++)); do
    a="$(envval "${names[$i]}")"; b="$(envval "${names[$j]}")"
    if [ -n "$a" ] && [ "$a" = "$b" ]; then dupes="$dupes ${names[$i]}=${names[$j]}"; fi
  done
done
if [ -n "$dupes" ]; then fail "These secrets share a value:$dupes. Generate a separate value for each."
else pass "The four secrets are all different"
fi

envmode="$(envval FENRIR_ENV)"
if [ -n "$envmode" ] && [ "$envmode" != "production" ]; then
  fail "FENRIR_ENV is '$envmode': the server's own safety checks are switched off. Remove the line or set production."
else
  pass "Production mode (the server refuses to start on unsafe settings)"
fi

public_url="$(envval FENRIR_PUBLIC_URL)"
public_url="${public_url%/}"
url_host="$(printf '%s' "$public_url" | sed -E 's#^[a-zA-Z]+://##; s#[/:].*$##')"
case "$public_url" in
  "") fail "FENRIR_PUBLIC_URL is empty. Agents and browsers use it to reach the server." ;;
  *example.com*|*example.org*) fail "FENRIR_PUBLIC_URL is still the template's example address ($public_url)." ;;
  https://*) pass "FENRIR_PUBLIC_URL uses HTTPS ($public_url)" ;;
  *) fail "FENRIR_PUBLIC_URL ($public_url) is not HTTPS: agents and browsers would send credentials unencrypted." ;;
esac

https_override=""
[ -f "$DEPLOY_DIR/docker-compose.https.yml" ] && https_override="$DEPLOY_DIR/docker-compose.https.yml"
if [ -n "$https_override" ]; then
  domain="$(envval FENRIR_DOMAIN)"
  if [ ! -f "$DEPLOY_DIR/Caddyfile" ]; then
    fail "deploy/docker-compose.https.yml is present but deploy/Caddyfile is not. Copy deploy/Caddyfile.example (README, step 4)."
  elif [ -n "$domain" ] && [ "$domain" != "$url_host" ]; then
    fail "FENRIR_DOMAIN ($domain) is not the host in FENRIR_PUBLIC_URL ($url_host): Caddy would get a certificate for the wrong name."
  else
    pass "HTTPS proxy configured (Caddy, $url_host)"
  fi
else
  warn "No deploy/docker-compose.https.yml. Fine if another proxy terminates TLS; otherwise follow README step 4."
fi

if [ "$(lower "$(envval FENRIR_OPEN_ENROLLMENT)")" = "false" ]; then
  pass "Open enrolment is off (machines need an enrolment token)"
else
  warn "FENRIR_OPEN_ENROLLMENT is not false (the Compose default is true): any machine that reaches the server can enrol and wait for approval."
fi
if truthy "$(envval FENRIR_IGNORE_CONSOLE_ALLOWLIST)"; then
  fail "FENRIR_IGNORE_CONSOLE_ALLOWLIST is on. It is a break-glass setting: fix the console network list and remove it."
fi
if [ "$(lower "$(envval FENRIR_REQUIRE_MFA)")" = "false" ]; then
  warn "FENRIR_REQUIRE_MFA is false: staff can sign in with a password alone."
else
  pass "Staff must use multi-factor authentication"
fi
legacy="$(envval FENRIR_VAULT_ALLOW_DERIVED_LEGACY)"
if [ -z "$legacy" ] || truthy "$legacy"; then
  warn "FENRIR_VAULT_ALLOW_DERIVED_LEGACY is on. On a new server set it to false; on an upgraded one, rotate the vault key first."
fi
metrics_token="$(envval FENRIR_METRICS_TOKEN)"
if [ -z "$metrics_token" ]; then
  note "No FENRIR_METRICS_TOKEN: /metrics is off. Set one to scrape Fenrir with Prometheus."
elif [ "${#metrics_token}" -lt 24 ]; then
  warn "FENRIR_METRICS_TOKEN is shorter than 24 characters, so /metrics stays off. Use: openssl rand -hex 24"
else
  pass "Prometheus metrics token set"
fi
if [ -z "$(envval FENRIR_SMTP_HOST)" ]; then
  warn "No SMTP server: alert and ticket emails are only logged, not sent."
else
  pass "SMTP configured ($(envval FENRIR_SMTP_HOST))"
fi

# ---------------------------------------------------------------------------------------------------------------------
section "Signing material (deploy/signing; contents are never printed)"
profile="$(envval FENRIR_BUILD_PROFILE)"; profile="${profile:-production}"
pfx="$DEPLOY_DIR/signing/codesign.pfx"
pfx_pw="$DEPLOY_DIR/signing/codesign.password"
azure_ts="$(envval FENRIR_CODESIGN_AZURE)"; azure_ts="${azure_ts:-$DEPLOY_DIR/signing/azure-trusted-signing.env}"
case "$azure_ts" in /*) ;; *) azure_ts="$DEPLOY_DIR/${azure_ts#./}" ;; esac
if [ "$profile" != "production" ]; then
  warn "FENRIR_BUILD_PROFILE is '$profile': Windows installers are not signed with your certificate. Not for customer machines."
elif [ -s "$azure_ts" ]; then
  missing=""
  for key in AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET TRUSTED_SIGNING_ENDPOINT TRUSTED_SIGNING_ACCOUNT TRUSTED_SIGNING_PROFILE; do
    grep -Eq "^[[:space:]]*$key[[:space:]]*=[[:space:]]*[^[:space:]]" "$azure_ts" || missing="$missing $key"
  done
  if [ -n "$missing" ]; then
    fail "Azure Trusted Signing settings ($azure_ts) are missing:$missing (docs/CODE_SIGNING.md)."
  elif loose_perms "$azure_ts"; then
    fail "The Azure Trusted Signing settings hold a client secret and can be read by other accounts. Run: chmod 600 $azure_ts"
  else
    pass "Azure Trusted Signing set up, owner-only (the build checks the credentials before compiling)"
  fi
elif [ ! -s "$pfx" ]; then
  fail "No Windows code signing: neither Azure Trusted Signing ($azure_ts) nor a certificate ($pfx). Production builds need one (docs/CODE_SIGNING.md)."
elif [ ! -f "$pfx_pw" ]; then
  fail "No $pfx_pw. Create it, empty if the certificate has no password (README, step 3)."
else
  if loose_perms "$pfx" || loose_perms "$pfx_pw"; then
    fail "The certificate or its password file can be read by other accounts. Run: chmod 600 $pfx $pfx_pw"
  else
    pass "Code-signing certificate and password present, owner-only"
  fi
  if have openssl; then
    if [ -s "$pfx_pw" ]; then pass_arg="file:$pfx_pw"; else pass_arg="pass:"; fi
    cert_end="$( { openssl pkcs12 -in "$pfx" -nokeys -clcerts -passin "$pass_arg" 2>/dev/null \
      || openssl pkcs12 -legacy -in "$pfx" -nokeys -clcerts -passin "$pass_arg" 2>/dev/null; } \
      | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    if [ -z "$cert_end" ]; then
      fail "The certificate cannot be opened with the stored password (wrong password or damaged file)."
    else
      days="$(days_until "$cert_end")"
      if [ -z "$days" ]; then note "Code-signing certificate expires $cert_end"
      elif [ "$days" -lt 0 ]; then fail "The code-signing certificate expired on $cert_end."
      elif [ "$days" -lt 30 ]; then warn "The code-signing certificate expires in $days days ($cert_end). Renew it."
      else pass "Code-signing certificate opens and is valid for $days more days"
      fi
    fi
  fi
fi

release_key="$(envval FENRIR_RELEASE_KEY)"; release_key="${release_key:-./signing/release-ed25519.pem}"
case "$release_key" in /*) ;; *) release_key="$DEPLOY_DIR/${release_key#./}" ;; esac
if [ ! -s "$release_key" ]; then
  warn "No Linux/macOS release key at $release_key. The first build creates one; agents then trust only that key (README, step 3)."
else
  if loose_perms "$release_key"; then
    fail "The release key can be read by other accounts. Run: chmod 600 $release_key"
  elif have openssl && ! openssl pkey -in "$release_key" -noout -text_pub 2>/dev/null | grep -qi 'ED25519'; then
    fail "The release key at $release_key is not an Ed25519 private key."
  else
    pass "Release signing key present, Ed25519, owner-only"
  fi
fi
note "backup.sh leaves out .env and deploy/signing on purpose. Keep offline copies of both: without FENRIR_VAULT_KEY a restored database's stored secrets cannot be read, and agents only accept updates signed with this release key."

# ---------------------------------------------------------------------------------------------------------------------
if [ "$NO_HOST" = 1 ]; then
  section "Host (skipped: --no-host)"
else
  section "Host"
  compose_args=(-f "$DEPLOY_DIR/docker-compose.yml")
  [ -n "$https_override" ] && compose_args+=(-f "$https_override")
  for f in ${FENRIR_COMPOSE_FILES:-}; do [ "$f" = "$https_override" ] || compose_args+=(-f "$f"); done

  if ! have docker; then
    fail "Docker is not installed."
  elif ! docker compose version >/dev/null 2>&1; then
    fail "The Docker Compose plugin is not installed (docker compose)."
  elif ! docker info >/dev/null 2>&1; then
    warn "Cannot talk to Docker as this account; run with sudo to check the containers."
  else
    pass "Docker and Compose available"
    running="$(docker compose "${compose_args[@]}" --env-file "$ENV_FILE" ps --status running --services 2>/dev/null)"
    want="db cloud worker"; [ -n "$https_override" ] && want="$want caddy"
    missing=""
    for s in $want; do printf '%s\n' "$running" | grep -qx "$s" || missing="$missing $s"; done
    if [ -n "$missing" ]; then fail "Containers not running:$missing. Check: docker compose ... ps, and logs."
    else pass "Containers running: $want"
    fi
  fi

  if have ss; then
    if [ -n "$https_override" ] && ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*|\[::\]):8080$'; then
      fail "Port 8080 is open on all interfaces, so plain HTTP bypasses Caddy. Bring the stack up with the HTTPS override."
    fi
    if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*|\[::\]):5432$'; then
      fail "PostgreSQL (5432) is listening on all interfaces. Do not publish the database port."
    fi
  fi

  check_disk() {  # check_disk PATH LABEL
    local line pct avail_kb
    line="$(df -Pk "$1" 2>/dev/null | tail -1)" || return 0
    [ -n "$line" ] || return 0
    avail_kb="$(echo "$line" | awk '{print $4}')"
    pct="$(echo "$line" | awk '{print $5}' | tr -d '%')"
    local gb=$(( avail_kb / 1048576 ))
    if [ "$pct" -ge 95 ]; then fail "$2 ($1) is ${pct}% full, ${gb} GB free."
    elif [ "$pct" -ge 85 ] || [ "$gb" -lt 10 ]; then warn "$2 ($1) is ${pct}% full, ${gb} GB free."
    else pass "$2 has ${gb} GB free (${pct}% used)"
    fi
  }
  docker_root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)"
  docker_root="${docker_root:-/var/lib/docker}"; [ -d "$docker_root" ] || docker_root=/
  check_disk "$docker_root" "Docker storage (database and telemetry)"
  [ -d "$BACKUP_DIR" ] && check_disk "$BACKUP_DIR" "Backup storage"

  schedule=""
  {
    crontab -l 2>/dev/null
    cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null
    ls /etc/cron.daily /etc/cron.weekly /etc/cron.hourly 2>/dev/null
    systemctl list-timers --all --no-legend 2>/dev/null
  } | grep -Eq 'backup\.sh|fenrir-backup' && schedule=yes
  latest=""
  if [ -d "$BACKUP_DIR" ]; then
    latest="$(find "$BACKUP_DIR" -maxdepth 1 \( -type d -name 'fenrir-backup-*' -o -type f -name 'fenrir-backup-*.tar.enc' \) -mtime -2 2>/dev/null | sort | tail -1)"
  fi
  if [ -n "$latest" ] && [ -s "$latest/manifest.json" ]; then
    pass "A backup from the last two days: $latest"
  elif [ -n "$latest" ]; then
    fail "The newest backup ($latest) has no manifest.json, so it did not finish."
  elif [ "$OFFLINE" = 1 ]; then
    warn "No backup in $BACKUP_DIR from the last two days (expected before the first start; required before go-live)."
  else
    fail "No backup in $BACKUP_DIR from the last two days. Run deploy/backup.sh (README, Backup and restore), or pass --backup-dir."
  fi
  if [ -n "$schedule" ]; then
    pass "Backups are scheduled (cron or systemd timer runs backup.sh)"
  else
    warn "No scheduled backup found. Add a daily cron entry or timer that runs deploy/backup.sh, and copy the result off this server."
  fi
  if systemctl is-enabled fenrir-auto-update.timer >/dev/null 2>&1; then
    note "Automatic updates are on (fenrir-auto-update.timer): every push to the tracked branch is deployed."
  fi
fi

# ---------------------------------------------------------------------------------------------------------------------
base="${URL_OVERRIDE:-$public_url}"; base="${base%/}"
if [ "$OFFLINE" = 1 ]; then
  section "Live server (skipped: --offline)"
elif [ -z "$base" ]; then
  section "Live server (skipped: no URL)"
elif ! have curl; then
  section "Live server"
  fail "curl is not installed, so the live server cannot be checked."
else
  section "Live server ($base)"
  body="$(mktemp)"; trap 'rm -f "$body"' EXIT
  get() {  # get PATH -> HTTP status, response in $body; certificate errors fail (no -k)
    local c; c="$(curl -sS -o "$body" -w '%{http_code}' --max-time 20 "$base$1" 2>/dev/null)" || true
    echo "${c:-000}"
  }
  code="$(get /health)"
  if [ "$code" = 200 ]; then
    pass "/health answers ($(sed -nE 's/.*"version": *"([^"]+)".*/version \1/p' "$body"))"
  elif [ "$code" = 000 ]; then
    fail "Cannot reach $base/health: not listening, DNS not pointing here, or the certificate is not trusted."
  else
    fail "/health returned HTTP $code."
  fi
  if [ "$code" != 000 ]; then
    code="$(get /ready)"
    if [ "$code" = 200 ] && grep -q '"ready": *true' "$body"; then
      pass "/ready: database up and schema current"
    else
      fail "/ready returned HTTP $code: $(tr -d '\n' < "$body" | cut -c1-160)"
    fi
    code="$(get /health/background)"
    if [ "$code" = 200 ]; then
      pass "/health/background: scheduler, maintenance and event outbox keeping up"
    else
      fail "/health/background returned HTTP $code: $(tr -d '\n' < "$body" | cut -c1-200). Check the worker container's logs."
    fi
    if [ "$profile" = production ]; then
      code="$(get /downloads/fenrir-codesign.cer)"
      if [ "$code" = 200 ]; then pass "Windows installers are code-signed (public certificate published)"
      else fail "The running build is not code-signed (/downloads/fenrir-codesign.cer returned $code). Rebuild with the certificate in place."
      fi
    fi
  fi
  case "$base" in
    https://*)
      host_port="$(printf '%s' "$base" | sed -E 's#^https://##; s#/.*$##')"
      host="${host_port%%:*}"; port="443"; [ "$host_port" != "$host" ] && port="${host_port##*:}"
      if have openssl; then
        tls_end="$(echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null \
          | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
        days="$( [ -n "$tls_end" ] && days_until "$tls_end")"
        if [ -z "$tls_end" ]; then warn "Could not read the TLS certificate from $host:$port."
        elif [ -z "$days" ]; then note "TLS certificate expires $tls_end"
        elif [ "$days" -lt 0 ]; then fail "The TLS certificate expired on $tls_end."
        elif [ "$days" -lt 14 ]; then warn "The TLS certificate expires in $days days and has not renewed. Check Caddy's logs."
        else pass "TLS certificate valid for $days more days"
        fi
      fi
      redirect="$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 "http://$host/health" 2>/dev/null || true)"
      case "$redirect" in
        30[1278]\ https://*) pass "Plain HTTP redirects to HTTPS" ;;
        "") note "Port 80 did not answer (fine if blocked; Caddy needs it to renew Let's Encrypt certificates)" ;;
        *) warn "Plain HTTP does not redirect to HTTPS (got: ${redirect:-nothing})." ;;
      esac
      ;;
    *) warn "Checked over plain HTTP ($base); go-live needs HTTPS." ;;
  esac
fi

# ---------------------------------------------------------------------------------------------------------------------
printf '\n%d passed, %d warnings, %d failed\n' "$passes" "$warns" "$fails"
if [ "$fails" -gt 0 ]; then
  echo "Not ready: fix every FAIL above, then run this again."
  exit 1
fi
if [ "$STRICT" = 1 ] && [ "$warns" -gt 0 ]; then
  echo "Not ready (--strict): decide on every WARN above."
  exit 1
fi
if [ "$warns" -gt 0 ]; then echo "Ready, with the warnings above to decide on."; else echo "Ready."; fi
exit 0
