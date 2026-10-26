# Brute-force protection

`firewall.bruteForceProtection` (on by default) blocks addresses that keep failing to sign in.

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Failed sign-ins read from | Security log, event 4625 (RDP and SMB/network logons) | `/var/log/auth.log` or `/var/log/secure`, otherwise the systemd journal (sshd) | Unified log (sshd), once a minute |
| Block applied with | Windows Firewall rule `Fenrir brute-force block <address>` (inbound, all ports) | nftables table `inet fenrir_bruteforce` (sets with a timeout) | pf anchor `com.apple/fenrir-bruteforce` |

Rules, identical on every agent (`BruteForceTracker.cpp` and `bruteforce.go`):

* 10 failures from one address within 10 minutes → blocked for 1 hour.
* Each repeat within a day blocks four times longer (4 h, 16 h), up to 24 hours.
* Loopback and unspecified addresses are never counted. Only plain IP addresses ever reach a firewall command.
* Sign-in failures from before the agent started are not counted.
* Turning the setting off lifts every block. On Windows, blocks survive an agent restart (`brute-force-blocks.json`). On Linux, nftables removes them itself when they time out.

Each block sends `auth.bruteforce.blocked`, which raises the **Brute-force source blocked by the agent** alert
(high, T1110). The payload lists the address, the number of failures, and the account names tried. When a
block ends, `auth.bruteforce.unblocked` is recorded.
