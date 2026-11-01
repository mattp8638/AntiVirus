# Network topology

The topology page shows two things for each customer:

- **Physical connections.** Which switch port each device is plugged into, and how the switches connect to each other.
- **Subnets.** Every device seen on each subnet, managed or not, behind its gateway.

## How connections are found

A **probe device** you choose on each site does the reading. Choose it under Network → Topology → Schedule. It queries the switches and routers listed under **Switch access**, using read-only SNMP (v2c, or v3 with authentication and privacy). It reads:

- **Switch identity:** name, description and bridge MAC.
- **Port names:** for example `Gi1/0/5`.
- **MAC address table:** which MAC was learned on which port, per VLAN where the switch supports it.
- **LLDP neighbours:** which switch or access point is on the far end of a port.
- **ARP table:** which IP address belongs to which MAC.

Fenrir then places each device on the port where it was learned that is not an uplink. An uplink is a port facing another known switch, found by LLDP or because the other switch's MAC was learned there. If a device was learned on several such ports, the port with the fewest devices wins, because that is the one nearest the device. A port with several devices on it is shown as "via an unmanaged switch or access point".

## Requirements and limits

- **Probe platform.** Switch ports are read only from **Linux or macOS probes**; a small VM or a Raspberry Pi on site is enough. Windows devices still map subnets. Native SNMP on Windows probes is a follow-up (decisions.md D-17).
- **Switch settings.** Each switch needs SNMP enabled for the probe's address. LLDP is optional but gives the switch-to-switch links their far-end port names.
- **Credential handling.** SNMP secrets are stored encrypted. They are never put in a command, and each one is released once, only to the probe the discovery was sent to. Releases are audited.
- **Safety limits.** Only private IPv4 addresses are queried, and only with read-only GET and GETBULK.
- **Failures.** A switch that doesn't answer is shown in Switch access with the reason. Fenrir never guesses its ports.
