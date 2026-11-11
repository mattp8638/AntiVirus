# shellcheck shell=bash
# Shared by setup.sh and reset.sh. Refuses to touch anything that is not this demo.
set -euo pipefail
DEMO_PROJECT=fenrir-demo
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file="$root/deploy/.env"
die() { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }
ok() { printf '    \033[32mOK\033[0m   %s\n' "$*"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
envget() { sed -n "s/^$1=//p" "$env_file" 2>/dev/null | tail -1; }
dc() {
  env COMPOSE_BAKE=false docker compose -p "$DEMO_PROJECT" -f "$root/deploy/docker-compose.yml" \
    -f "$root/deploy/docker-compose.lab.yml" -f "$root/deploy/demo/docker-compose.demo.yml" --env-file "$env_file" "$@"
}
require_demo_env() {
  [ -f "$env_file" ] || die "$env_file does not exist: run deploy/demo/setup.sh first"
  [ "$(envget FENRIR_DEMO_MODE)" = "true" ] || die "$env_file is not a demo configuration (FENRIR_DEMO_MODE=true missing). Refusing to touch it."
  [ -n "$(envget FENRIR_DEMO_SEED_TOKEN)" ] || die "FENRIR_DEMO_SEED_TOKEN is missing from $env_file"
  case "$(envget FENRIR_IMAGE)" in fenrir-demo*) ;; *) die "FENRIR_IMAGE in $env_file must start with fenrir-demo (keeps the live image untouched)";; esac
}
