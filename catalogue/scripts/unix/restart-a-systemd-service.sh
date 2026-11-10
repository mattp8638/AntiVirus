#!/bin/sh
# name: Restart a systemd service
# description: Restarts a service and shows its status.
# category: Services
# platforms: linux
# timeout: 300
# param: ServiceName | Service name | string |  | required
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
systemctl restart "$ServiceName" && systemctl status "$ServiceName" --no-pager -n 10
