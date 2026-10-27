//go:build legacy_ebpf

// Legacy eBPF + YARA prototype, superseded by cmd/fenrir-agent. Build with -tags legacy_ebpf (needs libyara and
// bpf2go output). Excluded by default so `go build ./...` and `go vet ./...` cover the shipped agent.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/hillu/go-yara/v4"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ebpf/sensor.c -- -I/usr/include/bpf

const (
	EventProcessStart   = 4
	EventNetworkConnect = 6
	EventFileWrite      = 2
)

// These structs must match the C structs
type ProcessStartEvent struct {
	EventType uint32
	Pid       uint32
	Uid       uint32
	Comm      [16]byte
	Filename  [256]byte
}

type NetworkConnectEvent struct {
	EventType uint32
	Pid       uint32
	Uid       uint32
	Comm      [16]byte
	Daddr     uint32
	Dport     uint16
	_         [2]byte // padding
}

type FileWriteEvent struct {
	EventType uint32
	Pid       uint32
	Uid       uint32
	Comm      [16]byte
	Filename  [256]byte
}

type TelemetryPayload struct {
	EventId   string      `json:"eventId"`
	DeviceId  string      `json:"deviceId"`
	Timestamp string      `json:"timestamp"`
	EventType string      `json:"eventType"`
	Payload   interface{} `json:"payload"`
}

var backendURL = "http://localhost:3000/api/v1/telemetry"

func bytesToString(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}

func ipv4ToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func sendTelemetry(payload TelemetryPayload) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
		return
	}

	resp, err := http.Post(backendURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to send telemetry: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Backend returned status %d", resp.StatusCode)
	}
}

func main() {
	if err := rlimit(); err != nil {
		log.Fatalf("Executing rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// Attach sys_execve
	execve, err := link.Kprobe("sys_execve", objs.KprobeSysExecve, nil)
	if err != nil {
		log.Fatalf("Opening kprobe sys_execve: %s", err)
	}
	defer execve.Close()

	// Attach tcp_v4_connect
	tcpv4, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("Opening kprobe tcp_v4_connect: %s", err)
	}
	defer tcpv4.Close()

	// Attach vfs_write
	vfswrite, err := link.Kprobe("vfs_write", objs.KprobeVfsWrite, nil)
	if err != nil {
		log.Fatalf("Opening kprobe vfs_write: %s", err)
	}
	defer vfswrite.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf event reader: %s", err)
	}
	defer rd.Close()

	log.Println("Fenrir Linux eBPF Agent running...")

	// Listen for interrupts
	go func() {
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		<-stopper
		log.Println("Received signal, exiting...")
		rd.Close()
		os.Exit(0)
	}()

	deviceId, _ := os.Hostname()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err)
			continue
		}

		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample[:4])
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

		var payload TelemetryPayload
		payload.DeviceId = deviceId
		payload.Timestamp = timestamp
		payload.EventId = fmt.Sprintf("%d-%d", time.Now().UnixNano(), eventType)

		switch eventType {
		case EventProcessStart:
			var event ProcessStartEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				payload.EventType = "ProcessStart"
				payload.Payload = map[string]interface{}{
					"eventType":   "ProcessStart",
					"processName": bytesToString(event.Comm[:]),
					"pid":         event.Pid,
					"commandLine": bytesToString(event.Filename[:]),
				}
				log.Printf("[Event] ProcessStart: %s %s (PID: %d)", bytesToString(event.Comm[:]), bytesToString(event.Filename[:]), event.Pid)
				sendTelemetry(payload)
			}
		case EventNetworkConnect:
			var event NetworkConnectEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				payload.EventType = "NetworkConnect"
				dport := ((event.Dport & 0xFF) << 8) | (event.Dport >> 8) // ntohs
				payload.Payload = map[string]interface{}{
					"eventType":       "NetworkConnect",
					"processName":     bytesToString(event.Comm[:]),
					"pid":             event.Pid,
					"destinationIp":   ipv4ToString(event.Daddr),
					"destinationPort": dport,
					"protocol":        "tcp4",
				}
				log.Printf("[Event] NetworkConnect: %s (PID: %d) -> %s:%d", bytesToString(event.Comm[:]), event.Pid, ipv4ToString(event.Daddr), dport)
				sendTelemetry(payload)
			}
		case EventFileWrite:
			var event FileWriteEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
				payload.EventType = "FileWrite"
				payload.Payload = map[string]interface{}{
					"eventType":   "FileWrite",
					"processName": bytesToString(event.Comm[:]),
					"pid":         event.Pid,
					"filePath":    bytesToString(event.Filename[:]),
				}
				log.Printf("[Event] FileWrite: %s (PID: %d) wrote to %s", bytesToString(event.Comm[:]), event.Pid, bytesToString(event.Filename[:]))
				sendTelemetry(payload)
			}
		}
	}
}

// rlimit removes the memory lock limit which is required for loading eBPF maps.
func rlimit() error {
	var rLimit syscall.Rlimit
	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = unix.RLIM_INFINITY
	return syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit)
}
