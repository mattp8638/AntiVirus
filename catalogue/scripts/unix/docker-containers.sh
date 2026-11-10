#!/bin/sh
# name: Docker containers
# description: Running and stopped containers, with disk use.
# category: Inventory
# platforms: linux
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
command -v docker >/dev/null 2>&1 || { echo 'Docker is not installed.'; exit 0; }
docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'; docker system df
