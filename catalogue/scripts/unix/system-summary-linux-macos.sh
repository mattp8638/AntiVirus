#!/bin/sh
# name: System summary (Linux/macOS)
# description: Host name, OS, kernel, uptime, CPU and memory.
# category: Inventory
# platforms: linux, macos
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
echo "Host:   $(hostname)"
if [ "$(uname -s)" = Darwin ]; then
  echo "OS:     $(sw_vers -productName) $(sw_vers -productVersion)"
  echo "Model:  $(sysctl -n hw.model)"; echo "CPU:    $(sysctl -n machdep.cpu.brand_string)"
  echo "Memory: $(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
else
  . /etc/os-release 2>/dev/null; echo "OS:     ${PRETTY_NAME:-unknown}"
  echo "CPU:    $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
  echo "Memory: $(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
fi
echo "Kernel: $(uname -r)"; echo "Uptime: $(uptime | sed 's/.*up \([^,]*\),.*/\1/')"
