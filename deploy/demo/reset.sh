#!/usr/bin/env bash
# Put the demo back to fresh sample data: wipes ONLY the fenrir-demo project's database and files, starts it again
# and reloads the sample customers, devices, alerts and tickets. Safe to run from cron (setup.sh installs it).
. "$(dirname "$0")/common.sh"
require_demo_env
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

step "Resetting the demo ($(date -u +%FT%TZ))"
# down -v removes the volumes of this compose project only: fenrir-demo_db and fenrir-demo_artifacts.
dc down -v --remove-orphans
dc up -d --wait --wait-timeout 300
ok "demo running with an empty database"

step "Loading sample data"
email="$(envget FENRIR_ADMIN_EMAIL)"
password="$(envget FENRIR_ADMIN_PASSWORD)"
dc exec -T cloud python -m fenrir_cloud.demo --url http://127.0.0.1:8080 --email "$email" --password "$password"
ok "sample data loaded; the demo is read-only again for visitors"
