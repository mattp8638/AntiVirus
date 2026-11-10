#!/usr/bin/env bash
# One-command Fenrir server install, from a fresh Ubuntu or Debian server to a running console with HTTPS.
#
#   From a checkout:   sudo deploy/install.sh --domain rmm.example.com --email you@example.com
#   Without one:       curl -fsSL <raw URL of this file> | sudo bash -s -- --domain rmm.example.com --email you@example.com --repo <git URL>
#
# What it does (each step is skipped when already done, so it is safe to run again):
#   1. checks the server (root, Ubuntu/Debian, 2 GB RAM, 15 GB disk, ports 80/443 free, the domain points here);
#   2. installs Docker Engine and Compose from the distribution's packages if missing;
#   3. writes deploy/.env with new random secrets (never overwrites an existing one);
#   4. creates this server's own Windows code-signing certificate (free, self-signed: the agent installer trusts it on
#      each device) and the Linux/macOS release key, unless signing material is already there;
#   5. sets up HTTPS with Caddy (Let's Encrypt certificates, renewed automatically);
#   6. builds and starts everything, waits until it is ready, and runs the go-live check;
#   7. schedules daily backups and, unless --no-auto-update, automatic updates from the stable release tags.
# At the end it prints the console address and the first administrator's sign-in.
#
# Options:
#   --domain NAME       hostname for the console and agents (required; its DNS A record must point at this server)
#   --email ADDRESS     first administrator's email, also used for Let's Encrypt notices (required)
#   --company NAME      your company name for the first-run MSP tenant and the signing certificate (default: "My MSP")
#   --dir PATH          where to put the checkout when not run from one (default /opt/fenrir)
#   --repo URL          git URL to clone when not run from a checkout
#   --branch NAME       branch or tag to clone (default: the repository's default branch)
#   --no-auto-update    do not install the automatic update timer
#   --skip-dns-check    install even if the domain does not resolve to this server yet
#   --yes               do not ask for confirmation
set -euo pipefail

domain="" email="" company="My MSP" dir="/opt/fenrir" repo="" branch="" auto_update=1 dns_check=1 assume_yes=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:-}"; shift 2 ;;
    --email) email="${2:-}"; shift 2 ;;
    --company) company="${2:-}"; shift 2 ;;
    --dir) dir="${2:-}"; shift 2 ;;
    --repo) repo="${2:-}"; shift 2 ;;
    --branch) branch="${2:-}"; shift 2 ;;
    --no-auto-update) auto_update=0; shift ;;
    --skip-dns-check) dns_check=0; shift ;;
    --yes|-y) assume_yes=1; shift ;;
    -h|--help) sed -n '2,32p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok() { printf '    \033[32mOK\033[0m   %s\n' "$*"; }
warn() { printf '    \033[33mWARN\033[0m %s\n' "$*"; }
die() { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
started=$(date +%s)

# --------------------------------------------------------------------------------------------------------------------
step "Checking the server"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo deploy/install.sh ...)"
[ -n "$domain" ] || die "--domain is required, e.g. --domain rmm.example.com"
[ -n "$email" ] || die "--email is required (the first administrator, and Let's Encrypt notices)"
case "$domain" in *://*|*/*|*" "*) die "--domain is a hostname only, without https:// or a path" ;; esac
echo "$domain" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$' \
  || die "--domain '$domain' is not a valid hostname"
echo "$email" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' || die "--email '$email' is not an email address"
company="$(printf '%s' "$company" | tr -cd 'A-Za-z0-9 ._&()-' | cut -c1-80)"; [ -n "$company" ] || company="My MSP"
. /etc/os-release 2>/dev/null || die "cannot identify this Linux distribution"
case "${ID:-}:${ID_LIKE:-}" in ubuntu:*|debian:*|*:*debian*) ok "${PRETTY_NAME:-$ID}" ;; *) die "this installer supports Ubuntu and Debian (found ${PRETTY_NAME:-$ID})" ;; esac
mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
[ "$mem_kb" -ge 1900000 ] && ok "$((mem_kb / 1024)) MB memory" || die "at least 2 GB of memory is needed (found $((mem_kb / 1024)) MB)"
free_gb=$(df -Pk "$(dirname "$dir")" | awk 'NR==2 {print int($4/1048576)}')
[ "$free_gb" -ge 15 ] && ok "${free_gb} GB free disk" || die "at least 15 GB of free disk is needed for the build (found ${free_gb} GB)"
command -v ss >/dev/null 2>&1 || apt-get install -y -qq iproute2 >/dev/null 2>&1 || true
for port in 80 443; do
  if ! command -v ss >/dev/null 2>&1; then warn "cannot check port $port (no ss)"; continue; fi
  if ss -ltnH "( sport = :$port )" 2>/dev/null | grep -q .; then
    owner=$(ss -ltnpH "( sport = :$port )" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1)
    case "$owner" in docker-proxy|caddy) ok "port $port already served by $owner (an earlier install)" ;;
      *) die "port $port is in use by ${owner:-another program}; Fenrir's HTTPS proxy needs ports 80 and 443" ;; esac
  else ok "port $port free"; fi
done
if [ "$dns_check" -eq 1 ]; then
  resolved=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1; exit}')
  public_ip=$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)
  if [ -z "$resolved" ]; then
    die "$domain does not resolve yet. Create an A record pointing at this server, wait a few minutes, then run again (or --skip-dns-check)."
  elif [ -n "$public_ip" ] && [ "$resolved" != "$public_ip" ]; then
    die "$domain points at $resolved but this server is $public_ip. Fix the A record (remove wrong AAAA records), or --skip-dns-check."
  fi
  ok "$domain resolves to ${resolved}"
fi
if [ "$assume_yes" -ne 1 ] && [ -t 0 ]; then
  printf '\nInstall Fenrir for https://%s with administrator %s? [y/N] ' "$domain" "$email"
  read -r answer; case "$answer" in y|Y|yes|YES) ;; *) die "cancelled" ;; esac
fi

# --------------------------------------------------------------------------------------------------------------------
step "Installing Docker and tools"
export DEBIAN_FRONTEND=noninteractive
need=()
for tool in git curl openssl; do command -v "$tool" >/dev/null 2>&1 || need+=("$tool"); done
command -v docker >/dev/null 2>&1 || need+=(docker.io)
docker compose version >/dev/null 2>&1 || need+=(docker-compose-v2)
if [ "${#need[@]}" -gt 0 ]; then
  apt-get update -qq
  # docker-compose-v2 is Ubuntu's package name; Debian ships the plugin as docker-compose.
  apt-get install -y -qq "${need[@]}" ca-certificates >/dev/null 2>&1 || {
    need=("${need[@]/docker-compose-v2/docker-compose}"); apt-get install -y -qq "${need[@]}" ca-certificates >/dev/null; }
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is not available; install it (https://docs.docker.com/compose/install/) and run again"
ok "$(docker --version | cut -d, -f1); $(docker compose version --short 2>/dev/null || echo compose v2)"

# --------------------------------------------------------------------------------------------------------------------
step "Getting Fenrir"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$script_dir" ] && [ -f "$script_dir/docker-compose.yml" ] && [ -d "$script_dir/../cloud" ]; then
  root="$(cd "$script_dir/.." && pwd)"
  ok "using this checkout: $root"
elif [ -d "$dir/.git" ]; then
  root="$dir"; ok "using the existing checkout in $root"
else
  [ -n "$repo" ] || die "not run from a checkout: pass --repo <git URL> (and optionally --dir)"
  git clone -q ${branch:+--branch "$branch"} "$repo" "$dir"
  root="$dir"; ok "cloned into $root"
fi
cd "$root"
umask 022

# --------------------------------------------------------------------------------------------------------------------
step "Configuration and secrets (deploy/.env)"
env_file=deploy/.env
set_env() {  # set_env KEY VALUE: replace or append, without printing the value
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" 'BEGIN{done=0} $0 ~ "^"k"=" {print k"="v; done=1; next} {print} END{if(!done) print k"="v}' "$env_file" > "$tmp"
  cat "$tmp" > "$env_file"; rm -f "$tmp"
}
if [ -s "$env_file" ]; then
  ok "kept the existing deploy/.env (its secrets protect your data; they are never regenerated)"
else
  (umask 077; cp deploy/.env.example "$env_file")
  admin_password="$(openssl rand -hex 12)"
  set_env POSTGRES_PASSWORD "$(openssl rand -hex 32)"
  set_env FENRIR_SECRET_KEY "$(openssl rand -hex 32)"
  set_env FENRIR_VAULT_KEY "$(openssl rand -base64 32)"
  set_env FENRIR_VAULT_ALLOW_DERIVED_LEGACY false
  set_env FENRIR_ADMIN_PASSWORD "$admin_password"
  set_env FENRIR_ADMIN_EMAIL "$email"
  set_env FENRIR_PUBLIC_URL "https://$domain"
  set_env FENRIR_DOMAIN "$domain"
  set_env FENRIR_OPEN_ENROLLMENT false
  set_env FENRIR_BUILD_PROFILE production
  set_env FENRIR_RELEASE_KEY ./signing/release-ed25519.pem
  set_env FENRIR_MSP_NAME "$company"
  chmod 600 "$env_file"
  ok "new secrets written (database, sessions, vault, first administrator)"
fi

# --------------------------------------------------------------------------------------------------------------------
step "Signing (free: this server's own certificate)"
(umask 077; mkdir -p deploy/signing deploy/releases)
chmod 700 deploy/signing
if [ -s deploy/signing/codesign.pfx ] || [ -s deploy/signing/azure-trusted-signing.env ]; then
  ok "kept the existing Windows signing set-up"
else
  work="$(mktemp -d)"; chmod 700 "$work"
  pfx_password="$(openssl rand -hex 16)"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 1825 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" \
    -subj "/CN=$company Fenrir agents/O=$company" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning" >/dev/null 2>&1
  (umask 077
   openssl pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" -out deploy/signing/codesign.pfx -passout "pass:$pfx_password"
   printf '%s' "$pfx_password" > deploy/signing/codesign.password)
  rm -rf "$work"
  ok "Windows code-signing certificate created (self-signed, 5 years). The agent installer trusts it on each device."
fi
if [ -s deploy/signing/release-ed25519.pem ]; then
  ok "kept the existing Linux/macOS release key"
else
  (umask 077; openssl genpkey -algorithm ed25519 -out deploy/signing/release-ed25519.pem)
  ok "Linux/macOS release signing key created"
fi
chmod 600 deploy/signing/* 2>/dev/null || true

# --------------------------------------------------------------------------------------------------------------------
step "HTTPS (Caddy, Let's Encrypt)"
[ -f deploy/docker-compose.https.yml ] || cp deploy/docker-compose.https.example.yml deploy/docker-compose.https.yml
if [ ! -f deploy/Caddyfile ]; then
  { printf '{\n    email %s\n}\n\n' "$email"; grep -v '^#' deploy/Caddyfile.example; } > deploy/Caddyfile
fi
ok "Caddy will obtain and renew the certificate for $domain"

dc() { env COMPOSE_BAKE=false docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.https.yml --env-file "$env_file" "$@"; }

# --------------------------------------------------------------------------------------------------------------------
step "Building and starting (the first build compiles the console and agents: allow 5-15 minutes)"
dc config --quiet || die "the Compose configuration is not valid; see the message above"
dc up -d --build
for i in $(seq 1 90); do
  if curl -fsS --max-time 5 http://127.0.0.1:8080/ready >/dev/null 2>&1; then ok "server ready"; break; fi
  [ "$i" -eq 90 ] && { dc logs --tail=80 cloud; die "the server did not become ready in 15 minutes; see the logs above"; }
  sleep 10
done
for i in $(seq 1 30); do
  if curl -fsS --max-time 8 "https://$domain/health" >/dev/null 2>&1; then ok "https://$domain answers with a valid certificate"; break; fi
  [ "$i" -eq 30 ] && warn "https://$domain is not answering yet (certificate still being issued, or ports 80/443 blocked by a firewall)"
  sleep 10
done

# --------------------------------------------------------------------------------------------------------------------
step "Backups and updates"
cat > /etc/cron.d/fenrir-backup <<EOF
17 2 * * * root cd $root && FENRIR_COMPOSE_FILES=$root/deploy/docker-compose.https.yml deploy/backup.sh /var/backups/fenrir >> /var/log/fenrir-backup.log 2>&1
EOF
ok "daily backup at 02:17 to /var/backups/fenrir (copy it off this server as well)"
if [ "$auto_update" -eq 1 ] && [ -x deploy/install-auto-update.sh ]; then
  deploy/install-auto-update.sh --stable >/dev/null 2>&1 && ok "automatic updates from stable releases" \
    || warn "could not install automatic updates; run deploy/install-auto-update.sh --stable later"
fi

# --------------------------------------------------------------------------------------------------------------------
step "Go-live check"
deploy/preflight.sh || warn "the go-live check found something to look at (above); the server is running"

elapsed=$(( $(date +%s) - started ))
printf '\n\033[1mFenrir is running.\033[0m (%d min %d s)\n\n' $((elapsed / 60)) $((elapsed % 60))
printf '  Console:   https://%s\n' "$domain"
printf '  Sign in:   %s\n' "$email"
if [ -n "${admin_password:-}" ]; then
  printf '  Password:  %s   (shown once: change it after signing in, and set up MFA)\n' "$admin_password"
else
  printf '  Password:  the FENRIR_ADMIN_PASSWORD in %s/deploy/.env when it was first installed\n' "$root"
fi
printf '\n  Firewall:  allow TCP 80 and 443, and UDP 3478 for direct (peer-to-peer) remote sessions.\n'
printf '\n  Next: Deploy agents > Deploy from your RMM, Group Policy or Intune.\n'
printf '  Keep %s/deploy/.env and deploy/signing/ backed up offline: they cannot be recreated.\n\n' "$root"
