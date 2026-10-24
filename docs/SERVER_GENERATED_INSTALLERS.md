# Server-generated customer installers

Docker compiles Windows x64 user-mode components on Ubuntu using MinGW and Linux amd64/arm64 components using Go. Source changes invalidate build layers. A failed compilation prevents deployment of the new image. No GitHub artifact download, release mount, certificate or manually pinned hash is required.

The authenticated deployment request creates a fresh customer/group-bound expiring enrollment token. Windows receives a single EXE with all native components and a bounded enrollment overlay. Linux receives a shell installer containing both compressed architecture binaries. Credentials are returned only to the authenticated caller, with no-store headers, and only their hash is persisted. Failed generation does not issue a token. Existing role and tenant checks apply.

After merging, redeploy on Ubuntu:

```sh
cd ~/AntiVirus
git pull
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build cloud
```

Select the OS/customer/group in Deploy agents and generate the download. Double-click the Windows EXE and approve administrator elevation. Linux requires sudo and systemd. macOS remains unavailable because its installable agent is unfinished. Windows is unsigned user-mode software; no kernel driver is included.

The first image build takes longer while the Windows payload compiles. Subsequent installer requests only package the already-built payload and enrollment settings. Existing FENRIR_WINDOWS_* staging settings are obsolete. Configure FENRIR_PUBLIC_URL to the HTTPS origin reachable by endpoints.

Validation: deployment API tests and console build; native Linux-hosted Windows cross-build. Real Windows installation, reboots, enrollment and commands must still be confirmed on the controlled VM. Docker runtime validation requires a Docker host.
