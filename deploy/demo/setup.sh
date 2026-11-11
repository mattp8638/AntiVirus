#!/usr/bin/env bash
# Set up a read-only public demo beside a live Fenrir on the same host. Run from a SEPARATE checkout:
#
#   sudo git clone https://github.com/Palmertech-Webdev/fenrir-security /opt/fenrir-demo && cd /opt/fenrir-demo
#   sudo deploy/demo/setup.sh --domain demo.example.com --live /opt/fenrir [--reset-hours 6] [--connect-live]
#
# It never changes the live install unless you pass --connect-live, and then only: it adds one site block to the live
# Caddyfile (backed up first, validated before reload) and attaches the live Caddy container to the fenrir-edge
# network. Without --connect-live it prints those two steps for you to do.
. "$(dirname "$0")/common.sh"

domain="" live="" hours=6 connect=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:-}"; shift 2 ;;
    --live) live="${2:-}"; shift 2 ;;
    --reset-hours) hours="${2:-}"; shift 2 ;;
    --connect-live) connect=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -n "$domain" ] || die "--domain is required (e.g. demo.example.com)"
echo "$domain" | grep -Eq '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' || die "--domain '$domain' is not a hostname"
echo "$hours" | grep -Eq '^([1-9]|1[0-9]|2[0-4])$' || die "--reset-hours must be 1-24"
command -v docker >/dev/null || die "Docker is not installed"
if [ -n "$live" ]; then
  live="$(cd "$live" && pwd)"
  [ "$live" != "$root" ] || die "this checkout IS the live install ($live). Clone the demo into its own folder."
fi
if [ -f "$env_file" ] && [ "$(envget FENRIR_DEMO_MODE)" != "true" ]; then
  die "$env_file exists and is not a demo configuration: this looks like a live install. Use a separate checkout."
fi

step "Demo configuration ($env_file)"
umask 077
if [ ! -f "$env_file" ]; then
  rand() { openssl rand -hex "$1"; }
  password="Demo-$(rand 4)"
  cat > "$env_file" <<CONF
# Read-only public demo. Everything here is throwaway: deploy/demo/reset.sh wipes it on a schedule.
FENRIR_DEMO_MODE=true
FENRIR_DEMO_SEED_TOKEN=$(rand 24)
FENRIR_DEMO_LOGIN=demo@$domain / $password
FENRIR_DEMO_RESET_NOTE=It resets to fresh sample data every $hours hours.
FENRIR_IMAGE=fenrir-demo-cloud:local
FENRIR_BUILD_PROFILE=lab
FENRIR_AGENTS=none
POSTGRES_PASSWORD=$(rand 20)
FENRIR_SECRET_KEY=$(rand 32)
FENRIR_VAULT_KEY=$(openssl rand -base64 32 | tr -d '\n')
FENRIR_VAULT_ALLOW_DERIVED_LEGACY=false
FENRIR_ADMIN_EMAIL=demo@$domain
FENRIR_ADMIN_PASSWORD=$password
FENRIR_MSP_NAME=Fenrir Demo
FENRIR_PUBLIC_URL=https://$domain
FENRIR_OPEN_ENROLLMENT=false
FENRIR_REQUIRE_MFA=false
FENRIR_FEED_SYNC=false
FENRIR_INTEL_FEEDS=false
FENRIR_DNS_BLOCKLISTS=false
CONF
  ok "new demo secrets and visitor login written"
else
  ok "keeping the existing demo configuration"
  grep -q '^FENRIR_AGENTS=' "$env_file" || { echo "FENRIR_AGENTS=none" >> "$env_file"; ok "demo builds skip agents from now on"; }
fi
require_demo_env

step "Network shared with the live Caddy"
docker network inspect fenrir-edge >/dev/null 2>&1 || docker network create fenrir-edge >/dev/null
ok "fenrir-edge"

step "Building and starting the demo (no agents are built: a few minutes)"
mkdir -p "$root/deploy/releases"
dc up -d --build --wait --wait-timeout 600
ok "demo containers running (project $DEMO_PROJECT, no host ports)"

"$root/deploy/demo/reset.sh"

step "Automatic reset every $hours hours"
cat > /etc/cron.d/fenrir-demo-reset <<CRON
# Put the Fenrir demo back to fresh sample data (deploy/demo/reset.sh)
17 */$hours * * * root $root/deploy/demo/reset.sh >> /var/log/fenrir-demo-reset.log 2>&1
CRON
chmod 644 /etc/cron.d/fenrir-demo-reset
ok "/etc/cron.d/fenrir-demo-reset (log: /var/log/fenrir-demo-reset.log)"

block="$domain {
    encode zstd gzip
    reverse_proxy fenrir-demo:8080
}"
caddy_container="$(docker ps --filter label=com.docker.compose.service=caddy --format '{{.Names}} {{.Label "com.docker.compose.project"}}' \
  | awk -v demo="$DEMO_PROJECT" '$2 != demo {print $1; exit}')"

step "Publishing through the live Caddy"
if [ "$connect" = 1 ]; then
  [ -n "$live" ] || die "--connect-live needs --live <path of the live install>"
  [ -n "$caddy_container" ] || die "no running live Caddy container found"
  # The Caddyfile the live container really reads: a file mounted at /etc/caddy/Caddyfile, or one inside a folder
  # mounted at /etc/caddy. Fall back to the standard deploy/Caddyfile only if neither is mounted.
  caddyfile="$(docker inspect "$caddy_container" --format '{{range .Mounts}}{{.Source}}|{{.Destination}}{{"\n"}}{{end}}' \
    | awk -F'|' '$2 == "/etc/caddy/Caddyfile" {print $1; exit} $2 == "/etc/caddy" {print $1 "/Caddyfile"; exit}')"
  [ -n "$caddyfile" ] || caddyfile="$live/deploy/Caddyfile"
  [ -f "$caddyfile" ] || die "$caddyfile not found (the live Caddy's config file)"
  ok "live Caddy reads $caddyfile"
  if ! grep -q "reverse_proxy fenrir-demo:8080" "$caddyfile"; then
    cp "$caddyfile" "$caddyfile.before-demo.$(date +%s)"
    printf '\n%s\n' "$block" >> "$caddyfile"
  fi
  docker network connect fenrir-edge "$caddy_container" 2>/dev/null || true
  if docker exec "$caddy_container" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    docker exec "$caddy_container" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
    docker exec "$caddy_container" grep -q "reverse_proxy fenrir-demo:8080" /etc/caddy/Caddyfile \
      || die "the live Caddy container does not see the demo entry in /etc/caddy/Caddyfile; nothing else was changed"
    ok "live Caddy now also serves https://$domain (it requests the certificate straight away)"
  else
    latest="$(ls -t "$caddyfile".before-demo.* | head -1)"; cp "$latest" "$caddyfile"
    die "the new Caddyfile did not validate; restored $caddyfile and left the live site unchanged"
  fi
else
  cat <<STEPS
    Nothing in the live install was changed. To publish the demo, add this to $( [ -n "$live" ] && echo "$live/" )deploy/Caddyfile:

$block

    then connect the live Caddy to the demo network and reload it:
      docker network connect fenrir-edge ${caddy_container:-<live caddy container>}
      docker exec ${caddy_container:-<live caddy container>} caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
    (or re-run this script with --live <live path> --connect-live to do both).
STEPS
fi
cat <<KEEP

    To keep the network link after the live Caddy is recreated, add to the caddy service in the live
    deploy/docker-compose.https.yml:      networks: [default, fenrir-edge]
    and at the end of that file:          networks: { fenrir-edge: { external: true, name: fenrir-edge } }

    DNS: point $domain at this server.  Visitor login: $(envget FENRIR_DEMO_LOGIN)
KEEP
