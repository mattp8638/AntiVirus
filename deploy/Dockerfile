# Fenrir Platform: cloud API + console + agent downloads in one image.
# Build from the repository root:  docker build -f deploy/Dockerfile -t fenrir-cloud .
# FENRIR_AGENTS=none builds the server without any agents or installers (the read-only demo uses it): the agent
# stages are then skipped entirely and /app/cloud/downloads holds only a note.
ARG FENRIR_AGENTS=build

FROM node:24.22.1-bookworm-slim AS console
WORKDIR /src/console
COPY console/package.json console/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
RUN npm run build

FROM golang:1.27.4-bookworm AS agents
WORKDIR /src/agent/linux
COPY agent/linux/ ./
# Release signing (FIX-07/AGT-03). The Ed25519 release key arrives as a BuildKit secret (never in a layer); its
# public key, plus any FENRIR_RELEASE_PUBLIC_KEYS (a key that signs offline, or the next key during a rotation),
# is pinned into the agents, which then install only releases those keys signed. FENRIR_RELEASE_SEQ numbers the
# release (auto-update.sh passes the git time of the last agent change); releases only move forwards.
# With no key (CI, lab without one) the agents keep the older hash-only update check.
ARG FENRIR_RELEASE_PUBLIC_KEYS=""
ARG FENRIR_RELEASE_SEQ=""
# BUILD_ID fingerprints the agent source: agents compare it with their own and upgrade themselves when it
# differs, so every server rebuild with agent changes rolls out without version bumps.
RUN --mount=type=secret,id=release_key \
    BUILD_ID=$(find . -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16) \
 && go build -trimpath -o /tmp/fenrir-release-sign ./cmd/fenrir-release-sign \
 && KEY=/run/secrets/release_key && PUBS="$FENRIR_RELEASE_PUBLIC_KEYS" && SIGNED=false \
 && if [ -s "$KEY" ]; then PUBS="$(/tmp/fenrir-release-sign -key "$KEY" -public)${PUBS:+,$PUBS}"; SIGNED=true; fi \
 && SEQ="${FENRIR_RELEASE_SEQ:-$(date +%s)}" \
 && PKG=github.com/AntiVirus/agent/linux/pkg/fleet \
 && LDFLAGS="-s -w -X $PKG.BuildID=$BUILD_ID -X $PKG.ReleaseSeq=$SEQ -X $PKG.ReleasePublicKeys=$PUBS" \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o /out/fenrir-agent-linux-amd64 ./cmd/fenrir-agent \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o /out/fenrir-agent-linux-arm64 ./cmd/fenrir-agent \
 && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o /out/fenrir-agent-darwin-amd64 ./cmd/fenrir-agent \
 && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" -o /out/fenrir-agent-darwin-arm64 ./cmd/fenrir-agent \
 && VERSION=$(sed -n 's/^const Version = "\(.*\)"/\1/p' pkg/fleet/agent.go) \
 && if [ "$SIGNED" = true ]; then /tmp/fenrir-release-sign -key "$KEY" -out /out -release "$SEQ" -version "$VERSION" -build-id "$BUILD_ID" \
      linux:amd64:/out/fenrir-agent-linux-amd64 linux:arm64:/out/fenrir-agent-linux-arm64 \
      macos:amd64:/out/fenrir-agent-darwin-amd64 macos:arm64:/out/fenrir-agent-darwin-arm64; fi \
 && sum() { sha256sum "$1" | cut -d' ' -f1; } \
 && printf '{"version":"%s","buildId":"%s","release":%s,"releaseSigned":%s,"pinnedReleaseKeys":%s,"sha256":{"amd64":"%s","arm64":"%s"},"darwinSha256":{"amd64":"%s","arm64":"%s"}}\n' \
      "$VERSION" "$BUILD_ID" "$SEQ" "$SIGNED" "$(echo "$PUBS" | awk -F, '{print (NF && $1 != "") ? NF : 0}')" \
      "$(sum /out/fenrir-agent-linux-amd64)" "$(sum /out/fenrir-agent-linux-arm64)" \
      "$(sum /out/fenrir-agent-darwin-amd64)" "$(sum /out/fenrir-agent-darwin-arm64)" \
      > /out/linux-build.json

# Automatically compile the unsigned Windows user-mode payload on Ubuntu.
# Docker's layer cache reuses it until agent source or its toolchain changes.
FROM ubuntu:24.04 AS windows-agents
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build g++-mingw-w64-x86-64-posix python3 osslsigncode openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY agent/windows/ agent/windows/
COPY third_party/sqlite/ third_party/sqlite/
COPY deploy/mingw-x64.cmake deploy/mingw-x64.cmake
COPY deploy/sign-windows.sh deploy/sign-windows.sh
# production (default): a code-signing certificate is required and checked before anything is compiled.
# lab: no certificate needed; the agents are built unsigned and labelled "unsigned-lab".
ARG FENRIR_BUILD_PROFILE=production
ENV FENRIR_BUILD_PROFILE=${FENRIR_BUILD_PROFILE}
# Code signing: Azure Trusted Signing settings (deploy/signing/azure-trusted-signing.env) or deploy/signing/codesign.pfx
# are passed as BuildKit secrets, so no key or credential lands in a layer. Components are signed first, the installer is rebuilt to embed the signed copies, then it is signed.
RUN --mount=type=secret,id=codesign_pfx --mount=type=secret,id=codesign_password --mount=type=secret,id=codesign_azure \
    SIGN_OUT=/tmp/signing-preflight sh deploy/sign-windows.sh \
 && find agent/windows third_party/sqlite deploy/mingw-x64.cmake -type f -not -path 'agent/windows/out/*' -print0 \
      | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16 > /build-id \
 && cmake -S agent/windows/service -B /build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=/src/deploy/mingw-x64.cmake -DFENRIR_BUILD_ID=$(cat /build-id) \
    -DCMAKE_BUILD_TYPE=Release -DANTIVIRUS_ENABLE_BUILD_VALIDATION=OFF \
    -DANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD=OFF \
    && cmake --build /build --target antivirus-setup --parallel 2 \
    && sh deploy/sign-windows.sh agent/windows/out/dev \
    && cmake --build /build --target antivirus-setup --parallel 2 \
    && sh deploy/sign-windows.sh agent/windows/out/install/FenrirSetup.exe \
    && mkdir -p /out/windows \
    && cp agent/windows/out/install/FenrirSetup.exe /out/windows/
# Setup must start on a clean Windows host before extracting any resources.
RUN x86_64-w64-mingw32-objdump -p /out/windows/FenrirSetup.exe > /out/windows/imports.txt && if grep -Ei 'DLL Name:.*(libwinpthread|libgcc|libstdc[+][+])' /out/windows/imports.txt; then echo "ERROR: setup depends on an external compiler runtime"; exit 1; fi
RUN python3 -c 'import hashlib,json,pathlib; p=pathlib.Path("/out/windows/FenrirSetup.exe"); sig=json.loads(pathlib.Path("/out/windows/signing.json").read_text()); p.with_name("build.json").write_text(json.dumps({"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"buildId":pathlib.Path("/build-id").read_text().strip(),"platform":"windows-x64","mode":"signed" if sig.get("signed") else "unsigned-lab","profile":"'"$FENRIR_BUILD_PROFILE"'",**sig}))'

# Device backup agent (backup/, Rust): static Linux build for this architecture, and Windows (also Hyper-V hosts)
# cross-compiled with MinGW. macOS builds come from CI (.github/workflows/backup.yml) into the same folder layout.
FROM rust:1.97-alpine AS backup-linux
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY backup/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p agent \
 && case "$(uname -m)" in \
      x86_64)  triple=x86_64-unknown-linux-musl ;; \
      aarch64) triple=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac \
 && mkdir -p /out/backup/$triple \
 && cp target/release/fenrir-backup-agent /out/backup/$triple/

FROM ubuntu:24.04 AS backup-windows
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates gcc gcc-mingw-w64-x86-64 libc6-dev \
 && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
COPY --from=rust:1.97-bookworm /usr/local/rustup /usr/local/rustup
COPY --from=rust:1.97-bookworm /usr/local/cargo /usr/local/cargo
RUN rustup target add x86_64-pc-windows-gnu
WORKDIR /src
COPY backup/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p agent --target x86_64-pc-windows-gnu \
 && mkdir -p /out/backup/x86_64-pc-windows-msvc \
 && cp target/x86_64-pc-windows-gnu/release/fenrir-backup-agent.exe /out/backup/x86_64-pc-windows-msvc/

FROM scratch AS backup-agents-build
COPY --from=backup-linux /out/backup/ /out/backup/
COPY --from=backup-windows /out/backup/ /out/backup/
FROM scratch AS backup-agents-none
COPY deploy/demo/no-agents/ /out/backup/

# Pick the agents to package: the stages above (build) or an empty placeholder (none). BuildKit skips any stage the
# final image does not use, so "none" never compiles an agent.
FROM scratch AS agents-none
COPY deploy/demo/no-agents/ /out/
FROM agents AS linux-agents-build
FROM agents-none AS linux-agents-none
FROM windows-agents AS windows-agents-build
FROM agents-none AS windows-agents-none
FROM linux-agents-${FENRIR_AGENTS} AS linux-agents
FROM windows-agents-${FENRIR_AGENTS} AS windows-agents-selected
FROM backup-agents-${FENRIR_AGENTS} AS backup-agents

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FENRIR_CONSOLE_DIR=/app/console/dist
WORKDIR /app/cloud
COPY cloud/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.2"
COPY cloud/ ./
COPY catalogue/ /app/catalogue/
COPY ml/fenrir_ml /app/ml/fenrir_ml
COPY ml/models /app/ml/models
COPY --from=console /src/console/dist /app/console/dist
COPY --from=linux-agents /out/ /app/cloud/downloads/
COPY --from=windows-agents-selected /out/windows/ /app/cloud/downloads/windows/
COPY --from=backup-agents /out/backup/ /app/cloud/downloads/backup/
# COPY preserves checkout permissions: a pull under umask 077 can leave source
# root-owned and unreadable to fenrir. Keep packaged code/assets readable and
# directories traversable, preserve executable agents, and remove group/other
# write access. Build secrets are mounted separately and never copied here.
# wixl (msitools) builds each customer's MSI on request (rmm_deploy.py).
# nmap and testssl.sh run authorised penetration test checks (docs/PENTEST.md); nmap uses TCP connect scans, so it
# needs no root or raw-socket capability. nuclei is optional: install it yourself and set FENRIR_PENTEST_NUCLEI.
RUN apt-get update && apt-get install -y --no-install-recommends wixl nmap testssl.sh && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 fenrir \
 && chmod -R a+rX,go-w /app \
 && mkdir -p /data && chown fenrir /data
USER fenrir
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/ready', timeout=4)"
CMD ["uvicorn", "--factory", "fenrir_cloud.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--workers", "1"]
