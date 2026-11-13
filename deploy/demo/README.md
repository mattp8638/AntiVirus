# Read-only public demo, beside your live server

A second Fenrir on the same host, for prospects to click around. It is locked down in the server itself
(`FENRIR_DEMO_MODE`):

- **No changes.** Every save, delete, run, approve or setting change is refused, whatever the visitor's role.
  Signing in and out are the only writes allowed.
- **No agents.** The demo image is built without any agents or installers (`FENRIR_AGENTS=none`), and enrolment,
  the agent API, downloads and remote sessions are closed as well.
- **Fresh every few hours.** `reset.sh` wipes the demo's own database and reloads the sample customers, devices,
  attacks, alerts and tickets. `setup.sh` schedules it (every 6 hours by default).

## How it stays apart from the live server

| | Live | Demo |
|---|---|---|
| Folder | e.g. `/opt/fenrir` | its own checkout, e.g. `/opt/fenrir-demo` |
| Settings and secrets | `deploy/.env` | its own `deploy/.env` (new random secrets) |
| Containers and volumes | project `deploy` | project `fenrir-demo` (`fenrir-demo_db`, `fenrir-demo_artifacts`) |
| Image | `fenrir-cloud:local` | `fenrir-demo-cloud:local` |
| Ports | 80/443 (Caddy), 3478/udp | none: reached only through the live Caddy |

The scripts refuse to run against a folder whose `.env` is not a demo configuration, and the reset only ever removes
the `fenrir-demo` project's volumes.

## Set up

```bash
sudo git clone https://github.com/<your-org>/<your-fork> /opt/fenrir-demo && cd /opt/fenrir-demo
sudo deploy/demo/setup.sh --domain demo.example.com --live /opt/fenrir --connect-live
```

- Point a DNS record for `demo.example.com` at the server first.
- `--connect-live` makes the only change to the live install: one site block appended to the Caddyfile its Caddy container actually reads (found from the container's mounts)
  (backed up, validated before reloading; restored if it does not validate) and the live Caddy container joined to
  the `fenrir-edge` network. Leave it out and the script prints both steps for you to do by hand.
- To keep that network link when the live Caddy container is recreated, add to the `caddy` service in the live
  `deploy/docker-compose.https.yml`: `networks: [default, fenrir-edge]`, and at the end of the file:
  `networks: { fenrir-edge: { external: true, name: fenrir-edge } }`.
- `--reset-hours 2` changes how often it resets (1-24).

The visitor login is shown on the demo's sign-in page and at the end of the setup output.

## Day to day

- Reset now: `sudo /opt/fenrir-demo/deploy/demo/reset.sh` (log of scheduled resets: `/var/log/fenrir-demo-reset.log`).
- Update the demo to newer code: `cd /opt/fenrir-demo && sudo git pull && sudo deploy/demo/setup.sh --domain demo.example.com`.
- Remove it: `sudo rm /etc/cron.d/fenrir-demo-reset`, then from `/opt/fenrir-demo` run
  `sudo docker compose -p fenrir-demo -f deploy/docker-compose.yml -f deploy/docker-compose.lab.yml -f deploy/demo/docker-compose.demo.yml --env-file deploy/.env down -v`,
  and delete its block from the live Caddyfile.
