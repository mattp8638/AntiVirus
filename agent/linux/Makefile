.PHONY: all agent agent-arm64 test generate build-ebpf clean

VERSION ?= 1.0.0
OUT ?= ../../dist/linux

# Managed agent: pure Go, static, no kernel requirements.
all: agent

agent:
	mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o $(OUT)/fenrir-agent-linux-amd64 ./cmd/fenrir-agent

agent-arm64:
	mkdir -p $(OUT)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o $(OUT)/fenrir-agent-linux-arm64 ./cmd/fenrir-agent

test:
	go vet ./pkg/fleet ./cmd/fenrir-agent
	go test ./pkg/fleet/

# Experimental eBPF sensor (needs clang, llvm, libbpf headers).
generate:
	go generate ./cmd/fenrir-linux-agent/...

build-ebpf: generate
	CGO_ENABLED=1 go build -o fenrir-linux-agent ./cmd/fenrir-linux-agent/

clean:
	rm -f fenrir-linux-agent cmd/fenrir-linux-agent/bpf_bpfel.go cmd/fenrir-linux-agent/bpf_bpfel.o
