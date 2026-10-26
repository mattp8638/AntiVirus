//go:build legacy_ebpf

// Legacy eBPF agent prototype (needs bpf2go-generated objects); the shipped agent is cmd/fenrir-agent.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/AntiVirus/agent/linux/pkg/broker"
	"github.com/AntiVirus/agent/linux/pkg/client"
	"github.com/AntiVirus/agent/linux/pkg/config"
	"github.com/AntiVirus/agent/linux/pkg/engine"
	"github.com/AntiVirus/agent/linux/pkg/inventory"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ../../ebpf/sensor.c -- -I/usr/include/bpf

const (
	EventProcessStart   = 4
	EventNetworkConnect = 6
	EventFileWrite      = 2
)

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
	_         [2]byte
}

type FileWriteEvent struct {
	EventType uint32
	Pid       uint32
	Uid       uint32
	Comm      [16]byte
	Filename  [256]byte
}

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

func main() {
	cfg := config.LoadConfig()

	if err := rlimit(); err != nil {
		log.Fatalf("Executing rlimit: %v", err)
	}

	// Initialise subsystems
	scanEngine := engine.NewScanEngine()
	if err := scanEngine.Initialize(); err != nil {
		log.Fatalf("ScanEngine init failed: %v", err)
	}

	processInventory := inventory.NewProcessInventory()
	controlPlaneClient := client.NewControlPlaneClient(cfg.BackendURL)
	protectionBroker := broker.NewRealtimeProtectionBroker(
		cfg.DeviceId,
		scanEngine,
		processInventory,
		controlPlaneClient,
	)

	// Load eBPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach kprobes
	execve, err := link.Kprobe("sys_execve", objs.KprobeSysExecve, nil)
	if err != nil {
		log.Fatalf("Opening kprobe sys_execve: %s", err)
	}
	defer execve.Close()

	tcpv4, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("Opening kprobe tcp_v4_connect: %s", err)
	}
	defer tcpv4.Close()

	vfswrite, err := link.Kprobe("vfs_write", objs.KprobeVfsWrite, nil)
	if err != nil {
		log.Fatalf("Opening kprobe vfs_write: %s", err)
	}
	defer vfswrite.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf event reader: %s", err)
	}
	defer rd.Close()

	log.Printf("Fenrir Linux eBPF Agent running. Device: %s, Backend: %s", cfg.DeviceId, cfg.BackendURL)

	// Signal handling
	go func() {
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		<-stopper
		log.Println("Signal received, flushing telemetry and exiting...")
		protectionBroker.FlushAll()
		rd.Close()
		os.Exit(0)
	}()

	// Main event loop
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

		switch eventType {
		case EventProcessStart:
			var ev ProcessStartEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err == nil {
				protectionBroker.ObserveEvent(broker.BehaviorEvent{
					EventType:   "ProcessStart",
					Pid:         ev.Pid,
					Uid:         ev.Uid,
					ProcessName: bytesToString(ev.Comm[:]),
					CommandLine: bytesToString(ev.Filename[:]),
				})
			}
		case EventNetworkConnect:
			var ev NetworkConnectEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err == nil {
				dport := ((ev.Dport & 0xFF) << 8) | (ev.Dport >> 8)
				protectionBroker.ObserveEvent(broker.BehaviorEvent{
					EventType:   "NetworkConnect",
					Pid:         ev.Pid,
					Uid:         ev.Uid,
					ProcessName: bytesToString(ev.Comm[:]),
					DestIP:      ipv4ToString(ev.Daddr),
					DestPort:    dport,
				})
			}
		case EventFileWrite:
			var ev FileWriteEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err == nil {
				protectionBroker.ObserveEvent(broker.BehaviorEvent{
					EventType:   "FileWrite",
					Pid:         ev.Pid,
					Uid:         ev.Uid,
					ProcessName: bytesToString(ev.Comm[:]),
					FilePath:    bytesToString(ev.Filename[:]),
				})
			}
		}
	}
}

func rlimit() error {
	var rLimit syscall.Rlimit
	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = unix.RLIM_INFINITY
	return syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit)
}
