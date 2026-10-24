# Fenrir Platform: cloud API + console + agent downloads in one image.
# Build from the repository root:  docker build -f deploy/Dockerfile -t fenrir-cloud .

FROM node:22.11-bookworm-slim AS console
WORKDIR /src/console
COPY console/package.json console/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY console/ ./
RUN npm run build

FROM golang:1.24-bookworm AS agents
WORKDIR /src/agent/linux
COPY agent/linux/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/fenrir-agent-linux-amd64 ./cmd/fenrir-agent \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /out/fenrir-agent-linux-arm64 ./cmd/fenrir-agent

# Build Windows user-mode agent and self-extracting Setup from source on the
# Ubuntu/Debian Docker host. This happens once per image rebuild, not on every
# customer download. There are no proprietary compilers or signing costs.
FROM debian:bookworm-slim AS windows-agent
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates cmake ninja-build python3 gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 \
    binutils-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY agent/windows/ /src/agent/windows/
COPY third_party/ /src/third_party/
COPY deploy/prepare_mingw_headers.py /src/deploy/prepare_mingw_headers.py
RUN python3 /src/deploy/prepare_mingw_headers.py \
      /usr/x86_64-w64-mingw32/include /src/agent/windows /opt/fenrir-windows-compat
RUN cmake -S agent/windows/service -B /tmp/fenrir-windows-build -G Ninja \
      -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
      -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
      -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
      -DCMAKE_C_FLAGS=-I/opt/fenrir-windows-compat \
      -DCMAKE_CXX_FLAGS=-I/opt/fenrir-windows-compat \
      -DANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD=OFF \
      -DANTIVIRUS_ENABLE_BUILD_VALIDATION=OFF \
 && cmake --build /tmp/fenrir-windows-build --target antivirus-setup --parallel 2 \
 && test -s /src/agent/windows/out/install/FenrirSetup.exe \
 && mkdir -p /out/windows \
 && cp /src/agent/windows/out/install/FenrirSetup.exe /out/windows/FenrirSetup.exe \
 && printf 'Windows cloud build template: ' \
 && sha256sum /out/windows/FenrirSetup.exe

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FENRIR_CONSOLE_DIR=/app/console/dist
WORKDIR /app/cloud
COPY cloud/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.2"
COPY cloud/ ./
COPY ml/fenrir_ml /app/ml/fenrir_ml
COPY ml/models /app/ml/models
COPY --from=console /src/console/dist /app/console/dist
COPY --from=agents /out/ /app/cloud/downloads/
# Read-only trusted Windows template, copied in automatically. No host mount.
COPY --from=windows-agent /out/windows/ /app/cloud/downloads/windows/
RUN useradd --system --uid 10001 fenrir && mkdir -p /data && chown fenrir /data
USER fenrir
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["uvicorn", "--factory", "fenrir_cloud.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--workers", "1"]
