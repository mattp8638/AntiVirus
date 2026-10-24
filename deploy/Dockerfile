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

# Automatically compile the unsigned Windows user-mode payload on Ubuntu.
# Docker's layer cache reuses it until agent source or its toolchain changes.
FROM ubuntu:24.04 AS windows-agents
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build g++-mingw-w64-x86-64-posix python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY agent/windows/ agent/windows/
COPY third_party/sqlite/ third_party/sqlite/
COPY deploy/mingw-x64.cmake deploy/mingw-x64.cmake
RUN cmake -S agent/windows/service -B /build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=/src/deploy/mingw-x64.cmake \
    -DCMAKE_BUILD_TYPE=Release -DANTIVIRUS_ENABLE_BUILD_VALIDATION=OFF \
    -DANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD=OFF \
    && cmake --build /build --target antivirus-setup --parallel 2 \
    && mkdir -p /out/windows \
    && cp agent/windows/out/install/FenrirSetup.exe /out/windows/
# Setup must start on a clean Windows host before extracting any resources.
RUN x86_64-w64-mingw32-objdump -p /out/windows/FenrirSetup.exe > /out/windows/imports.txt \\
    && if grep -Ei 'DLL Name:.*(libwinpthread|libgcc|libstdc++)' /out/windows/imports.txt; then \\
         echo "ERROR: setup depends on an external compiler runtime"; exit 1; fi
RUN python3 -c 'import hashlib,json,pathlib; p=pathlib.Path("/out/windows/FenrirSetup.exe"); p.with_name("build.json").write_text(json.dumps({"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"platform":"windows-x64","mode":"unsigned-hobby"}))'

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
COPY --from=windows-agents /out/windows/ /app/cloud/downloads/windows/
RUN useradd --system --uid 10001 fenrir && mkdir -p /data && chown fenrir /data
USER fenrir
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["uvicorn", "--factory", "fenrir_cloud.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--workers", "1"]
