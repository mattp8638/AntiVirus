package inventory

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type DeviceInventory struct {
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	KernelVersion string    `json:"kernelVersion"`
	Architecture  string    `json:"architecture"`
	CPUModel      string    `json:"cpuModel"`
	MemoryTotalMB uint64    `json:"memoryTotalMb"`
	Distro        string    `json:"distro"`
	CollectedAt   time.Time `json:"collectedAt"`
}

func CollectDeviceInventory() (*DeviceInventory, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return nil, fmt.Errorf("uname: %w", err)
	}

	hostname, _ := os.Hostname()

	return &DeviceInventory{
		Hostname:      hostname,
		OS:            "Linux",
		KernelVersion: charsToString(uname.Release[:]),
		Architecture:  runtime.GOARCH,
		CPUModel:      readCPUModel(),
		MemoryTotalMB: readTotalMemoryMB(),
		Distro:        readDistro(),
		CollectedAt:   time.Now(),
	}, nil
}

func readCPUModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}

func readTotalMemoryMB() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			var kb uint64
			fmt.Sscanf(line, "MemTotal: %d kB", &kb)
			return kb / 1024
		}
	}
	return 0
}

func readDistro() string {
	out, err := exec.Command("lsb_release", "-d", "-s").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	// Fallback: read /etc/os-release
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return "unknown"
}

// charsToString reads a NUL-terminated utsname field ([]int8 or []uint8 depending on the architecture).
func charsToString[T int8 | uint8](ca []T) string {
	b := make([]byte, 0, len(ca))
	for _, c := range ca {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
