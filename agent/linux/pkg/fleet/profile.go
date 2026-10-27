package fleet

// The system profile on Linux and macOS: hardware, disks with SMART health, volumes and encryption, users and
// sessions, network, battery, security posture, recent errors and failed services. Same layout as the Windows
// agent's profile (see the cloud's routers/device_profile.py). Every section is best effort: a missing tool
// (smartctl, lsblk, system_profiler...) leaves that section empty.

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const profileInterval = 6 * time.Hour

func profileCmd(timeout time.Duration, name string, args ...string) string {
	if _, err := exec.LookPath(name); err != nil {
		return ""
	}
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	go func() { out, _ = cmd.Output(); close(done) }()
	select {
	case <-done:
		return string(out)
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ""
	}
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func gb(bytes float64) float64 { return float64(int64(bytes/(1<<30)*10)) / 10 }

// CollectProfile builds the profile document for this machine.
func CollectProfile() map[string]interface{} {
	p := map[string]interface{}{"collectedAt": time.Now().UTC().Format(time.RFC3339), "platform": runtime.GOOS}
	if IsMacOS {
		collectMacProfile(p)
	} else {
		collectLinuxProfile(p)
	}
	p["network"] = profileNetwork()
	return p
}

func collectLinuxProfile(p map[string]interface{}) {
	dmi := func(name string) string { return readTrim("/sys/class/dmi/id/" + name) }
	cpuName, threads := "", runtime.NumCPU()
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
				cpuName = strings.TrimSpace(v)
				break
			}
		}
		f.Close()
	}
	memTotal := 0.0
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.ParseFloat(fields[1], 64)
					memTotal = gb(kb * 1024)
				}
			}
		}
	}
	_, tpmErr := os.Stat("/sys/class/tpm/tpm0")
	var secureBoot interface{}
	if matches, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*"); len(matches) > 0 {
		if data, err := os.ReadFile(matches[0]); err == nil && len(data) >= 5 {
			secureBoot = data[4] == 1
		}
	}
	p["hardware"] = map[string]interface{}{
		"manufacturer": dmi("sys_vendor"), "model": dmi("product_name"), "serial": dmi("product_serial"),
		"biosVersion": dmi("bios_version"), "biosDate": dmi("bios_date"),
		"cpu":        map[string]interface{}{"name": cpuName, "threads": threads},
		"memory":     map[string]interface{}{"totalGb": memTotal},
		"tpm":        map[string]interface{}{"present": tpmErr == nil},
		"secureBoot": secureBoot,
	}

	osName, version := "", ""
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "PRETTY_NAME":
				osName = v
			case "VERSION_ID":
				version = v
			}
		}
	}
	var lastBoot string
	if fields := strings.Fields(readTrim("/proc/uptime")); len(fields) > 0 {
		if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
			lastBoot = time.Now().Add(-time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339)
		}
	}
	_, rebootErr := os.Stat("/var/run/reboot-required")
	reasons := []string{}
	if rebootErr == nil {
		reasons = append(reasons, "Package updates")
	}
	hostname, _ := os.Hostname()
	p["os"] = map[string]interface{}{
		"name": osName, "version": version, "build": strings.TrimSpace(profileCmd(5*time.Second, "uname", "-r")), "architecture": runtime.GOARCH,
		"lastBoot": lastBoot, "timezone": readTrim("/etc/timezone"), "hostname": hostname,
		"rebootPending": rebootErr == nil, "rebootReasons": reasons,
	}

	p["disks"] = linuxDisks()
	p["volumes"] = linuxVolumes()
	p["users"] = linuxUsers()
	p["battery"] = linuxBattery()

	firewall := []map[string]interface{}{}
	if out := profileCmd(10*time.Second, "ufw", "status"); out != "" {
		firewall = append(firewall, map[string]interface{}{"profile": "ufw", "enabled": strings.Contains(out, "Status: active")})
	} else if out := profileCmd(10*time.Second, "nft", "list", "ruleset"); out != "" {
		firewall = append(firewall, map[string]interface{}{"profile": "nftables", "enabled": strings.Contains(out, "hook input")})
	}
	sshdRoot := ""
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "PermitRootLogin") {
				sshdRoot = fields[1]
			}
		}
	}
	p["security"] = map[string]interface{}{"firewall": firewall, "sshRootLogin": sshdRoot,
		"selinux": strings.TrimSpace(profileCmd(5*time.Second, "getenforce")), "apparmor": readTrim("/sys/module/apparmor/parameters/enabled") == "Y"}

	errors24 := 0
	if out := profileCmd(30*time.Second, "journalctl", "-p", "3", "--since", "24 hours ago", "-q", "--no-pager", "-o", "cat"); out != "" {
		errors24 = len(strings.Split(strings.TrimSpace(out), "\n"))
	}
	recent := []map[string]interface{}{}
	if out := profileCmd(30*time.Second, "journalctl", "-p", "3", "--since", "7 days ago", "-q", "--no-pager", "-o", "json", "-n", "25", "-r"); out != "" {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			var entry map[string]interface{}
			if json.Unmarshal([]byte(line), &entry) != nil {
				continue
			}
			when := ""
			if us, err := strconv.ParseInt(str(entry["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
				when = time.UnixMicro(us).UTC().Format(time.RFC3339)
			}
			recent = append(recent, map[string]interface{}{"time": when, "source": str(entry["SYSLOG_IDENTIFIER"]), "level": "Error",
				"message": truncate(str(entry["MESSAGE"]), 300)})
		}
	}
	p["events"] = map[string]interface{}{"errorsLast24h": errors24, "recent": recent}

	failed := []string{}
	for _, line := range strings.Split(profileCmd(10*time.Second, "systemctl", "--failed", "--plain", "--no-legend"), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			failed = append(failed, fields[0])
		}
	}
	p["services"] = map[string]interface{}{"autoStopped": failed}
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type lsblkDevice struct {
	Name       string        `json:"name"`
	Model      string        `json:"model"`
	Serial     string        `json:"serial"`
	Size       interface{}   `json:"size"`
	Rota       interface{}   `json:"rota"`
	Tran       string        `json:"tran"`
	Type       string        `json:"type"`
	FSType     string        `json:"fstype"`
	Mountpoint string        `json:"mountpoint"`
	Children   []lsblkDevice `json:"children"`
}

func toFloat(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

func linuxDisks() []map[string]interface{} {
	var doc struct {
		Blockdevices []lsblkDevice `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(profileCmd(15*time.Second, "lsblk", "-J", "-b", "-d", "-o", "NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,TYPE")), &doc) != nil {
		return nil
	}
	out := []map[string]interface{}{}
	for _, d := range doc.Blockdevices {
		if d.Type != "disk" || strings.HasPrefix(d.Name, "loop") || strings.HasPrefix(d.Name, "zram") || toFloat(d.Size) < 1<<30 {
			continue
		}
		media := "SSD"
		if toFloat(d.Rota) == 1 {
			media = "HDD"
		}
		disk := map[string]interface{}{"name": "/dev/" + d.Name, "model": strings.TrimSpace(d.Model), "serial": strings.TrimSpace(d.Serial),
			"sizeGb": gb(toFloat(d.Size)), "mediaType": media, "busType": strings.ToUpper(d.Tran)}
		// SMART, when smartmontools is installed.
		var smart map[string]interface{}
		if json.Unmarshal([]byte(profileCmd(20*time.Second, "smartctl", "-j", "-H", "-A", "/dev/"+d.Name)), &smart) == nil && smart != nil {
			if status, ok := smart["smart_status"].(map[string]interface{}); ok {
				if passed, ok := status["passed"].(bool); ok {
					disk["smartOk"] = passed
					disk["health"] = map[bool]string{true: "Healthy", false: "Failing"}[passed]
				}
			}
			if t, ok := smart["temperature"].(map[string]interface{}); ok {
				disk["temperatureC"] = toFloat(t["current"])
			}
			if t, ok := smart["power_on_time"].(map[string]interface{}); ok {
				disk["powerOnHours"] = toFloat(t["hours"])
			}
			if nvme, ok := smart["nvme_smart_health_information_log"].(map[string]interface{}); ok {
				disk["wearPercent"] = toFloat(nvme["percentage_used"])
				disk["readErrors"] = toFloat(nvme["media_errors"])
			}
		}
		out = append(out, disk)
	}
	return out
}

func linuxVolumes() []map[string]interface{} {
	encrypted := map[string]bool{}
	var tree struct {
		Blockdevices []lsblkDevice `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(profileCmd(15*time.Second, "lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT")), &tree) == nil {
		var walk func(devs []lsblkDevice, underCrypt bool)
		walk = func(devs []lsblkDevice, underCrypt bool) {
			for _, d := range devs {
				crypt := underCrypt || d.Type == "crypt"
				if d.Mountpoint != "" {
					encrypted[d.Mountpoint] = crypt
				}
				walk(d.Children, crypt)
			}
		}
		walk(tree.Blockdevices, false)
	}
	out := []map[string]interface{}{}
	lines := strings.Split(profileCmd(15*time.Second, "df", "-B1", "-T", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs"), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		size, _ := strconv.ParseFloat(f[2], 64)
		avail, _ := strconv.ParseFloat(f[4], 64)
		if size < 1<<30 {
			continue
		}
		mount := f[6]
		protection := "Off"
		if encrypted[mount] {
			protection = "On"
		}
		out = append(out, map[string]interface{}{"mount": mount, "label": f[0], "fileSystem": f[1], "sizeGb": gb(size), "freeGb": gb(avail),
			"system": mount == "/", "encryption": map[string]interface{}{"protection": protection, "method": map[bool]string{true: "LUKS", false: ""}[encrypted[mount]]}})
	}
	return out
}

func linuxUsers() map[string]interface{} {
	admins := map[string]bool{}
	if data, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) == 4 && (parts[0] == "sudo" || parts[0] == "wheel" || parts[0] == "admin") {
				for _, member := range strings.Split(parts[3], ",") {
					if member != "" {
						admins[member] = true
					}
				}
			}
		}
	}
	local := []map[string]interface{}{}
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 7 {
				continue
			}
			uid, _ := strconv.Atoi(parts[2])
			if (uid < 1000 && uid != 0) || uid == 65534 || strings.HasSuffix(parts[6], "nologin") || strings.HasSuffix(parts[6], "false") {
				continue
			}
			local = append(local, map[string]interface{}{"name": parts[0], "fullName": strings.Split(parts[4], ",")[0], "enabled": true,
				"admin": uid == 0 || admins[parts[0]], "home": parts[5], "shell": parts[6]})
		}
	}
	sessions := []map[string]interface{}{}
	for _, line := range strings.Split(profileCmd(5*time.Second, "who"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			s := map[string]interface{}{"user": f[0], "session": f[1], "logonTime": f[2] + " " + f[3], "state": "Active"}
			if len(f) >= 5 {
				s["client"] = strings.Trim(f[4], "()")
			}
			sessions = append(sessions, s)
		}
	}
	return map[string]interface{}{"local": local, "sessions": sessions}
}

func linuxBattery() map[string]interface{} {
	matches, _ := filepath.Glob("/sys/class/power_supply/BAT*")
	if len(matches) == 0 {
		return map[string]interface{}{"present": false}
	}
	dir := matches[0]
	value := func(names ...string) float64 {
		for _, n := range names {
			if v := readTrim(filepath.Join(dir, n)); v != "" {
				f, _ := strconv.ParseFloat(v, 64)
				return f
			}
		}
		return 0
	}
	design, full := value("energy_full_design", "charge_full_design"), value("energy_full", "charge_full")
	b := map[string]interface{}{"present": true, "chargePercent": value("capacity"), "status": readTrim(filepath.Join(dir, "status")),
		"designCapacity": design, "fullChargeCapacity": full, "cycleCount": value("cycle_count")}
	if design > 0 && full > 0 {
		b["healthPercent"] = float64(int(100 * full / design))
	}
	return b
}

func profileNetwork() map[string]interface{} {
	gateway := ""
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == "00000000" {
				if raw, err := strconv.ParseUint(f[2], 16, 32); err == nil {
					gateway = net.IPv4(byte(raw), byte(raw>>8), byte(raw>>16), byte(raw>>24)).String()
				}
			}
		}
	}
	dns := []string{}
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
				dns = append(dns, f[1])
			}
		}
	}
	adapters := []map[string]interface{}{}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "br-") || strings.HasPrefix(iface.Name, "utun") || strings.HasPrefix(iface.Name, "awdl") {
			continue
		}
		v4, v6 := []string{}, []string{}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ones, _ := ipnet.Mask.Size()
					v4 = append(v4, ipnet.IP.String()+"/"+strconv.Itoa(ones))
				} else if !ipnet.IP.IsLinkLocalUnicast() {
					v6 = append(v6, ipnet.IP.String())
				}
			}
		}
		if len(v4) == 0 && len(v6) == 0 && iface.Flags&net.FlagUp == 0 {
			continue
		}
		status := "Down"
		if iface.Flags&net.FlagUp != 0 {
			status = "Up"
		}
		speed := ""
		if s := readTrim("/sys/class/net/" + iface.Name + "/speed"); s != "" && s != "-1" {
			speed = s + " Mbps"
		}
		adapters = append(adapters, map[string]interface{}{"name": iface.Name, "mac": iface.HardwareAddr.String(), "status": status,
			"speed": speed, "ipv4": v4, "ipv6": v6, "gateway": []string{gateway}, "dns": dns})
	}
	sort.Slice(adapters, func(i, j int) bool { return str(adapters[i]["name"]) < str(adapters[j]["name"]) })
	return map[string]interface{}{"adapters": adapters}
}

func collectMacProfile(p map[string]interface{}) {
	var sp map[string][]map[string]interface{}
	_ = json.Unmarshal([]byte(profileCmd(60*time.Second, "system_profiler", "-json", "SPHardwareDataType", "SPPowerDataType", "SPStorageDataType",
		"SPNVMeDataType", "SPSerialATADataType", "SPSoftwareDataType")), &sp)
	first := func(key string) map[string]interface{} {
		if items := sp[key]; len(items) > 0 {
			return items[0]
		}
		return map[string]interface{}{}
	}
	hw := first("SPHardwareDataType")
	p["hardware"] = map[string]interface{}{"manufacturer": "Apple", "model": str(hw["machine_model"]), "modelName": str(hw["machine_name"]),
		"serial": str(hw["serial_number"]), "biosVersion": str(hw["boot_rom_version"]),
		"cpu":    map[string]interface{}{"name": firstNonEmpty(str(hw["chip_type"]), str(hw["cpu_type"])), "threads": runtime.NumCPU()},
		"memory": map[string]interface{}{"total": str(hw["physical_memory"])}}
	sw := first("SPSoftwareDataType")
	var lastBoot string
	if out := strings.TrimSpace(profileCmd(5*time.Second, "sysctl", "-n", "kern.boottime")); out != "" {
		if i := strings.Index(out, "sec = "); i >= 0 {
			if sec, err := strconv.ParseInt(strings.Trim(strings.Fields(out[i+6:])[0], ","), 10, 64); err == nil {
				lastBoot = time.Unix(sec, 0).UTC().Format(time.RFC3339)
			}
		}
	}
	p["os"] = map[string]interface{}{"name": str(sw["os_version"]), "build": str(sw["kernel_version"]), "lastBoot": lastBoot,
		"architecture": runtime.GOARCH, "secureVM": str(sw["secure_vm"])}

	disks := []map[string]interface{}{}
	for _, key := range []string{"SPNVMeDataType", "SPSerialATADataType"} {
		for _, bus := range sp[key] {
			items, _ := bus["_items"].([]interface{})
			for _, raw := range items {
				d, _ := raw.(map[string]interface{})
				health := str(d["smart_status"])
				disks = append(disks, map[string]interface{}{"name": str(d["_name"]), "model": str(d["device_model"]), "serial": str(d["device_serial"]),
					"health": map[bool]string{true: "Healthy", false: health}[strings.EqualFold(health, "Verified")], "smartOk": strings.EqualFold(health, "Verified"),
					"mediaType": "SSD", "busType": strings.TrimSuffix(key[2:], "DataType")})
			}
		}
	}
	p["disks"] = disks
	fileVault := strings.Contains(profileCmd(10*time.Second, "fdesetup", "status"), "FileVault is On")
	volumes := []map[string]interface{}{}
	for _, v := range sp["SPStorageDataType"] {
		size, free := toFloat(v["size_in_bytes"]), toFloat(v["free_space_in_bytes"])
		mount := str(v["mount_point"])
		if size < 1<<30 || mount == "" {
			continue
		}
		protection := "Off"
		if mount == "/" && fileVault {
			protection = "On"
		}
		volumes = append(volumes, map[string]interface{}{"mount": mount, "label": str(v["_name"]), "fileSystem": str(v["file_system"]),
			"sizeGb": gb(size), "freeGb": gb(free), "system": mount == "/",
			"encryption": map[string]interface{}{"protection": protection, "method": map[bool]string{true: "FileVault", false: ""}[mount == "/" && fileVault]}})
	}
	p["volumes"] = volumes
	power := first("SPPowerDataType")
	battery := map[string]interface{}{"present": false}
	if health, ok := power["sppower_battery_health_info"].(map[string]interface{}); ok {
		battery = map[string]interface{}{"present": true, "cycleCount": toFloat(health["sppower_battery_cycle_count"]),
			"condition": str(health["sppower_battery_health"])}
		if pct := strings.TrimSuffix(str(health["sppower_battery_health_maximum_capacity"]), "%"); pct != "" {
			if f, err := strconv.ParseFloat(pct, 64); err == nil {
				battery["healthPercent"] = f
			}
		}
	}
	p["battery"] = battery
	local := []map[string]interface{}{}
	admins := map[string]bool{}
	for _, name := range strings.Fields(strings.TrimPrefix(strings.TrimSpace(profileCmd(10*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")), "GroupMembership:")) {
		admins[name] = true
	}
	for _, line := range strings.Split(profileCmd(10*time.Second, "dscl", ".", "-list", "/Users", "UniqueID"), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if uid, _ := strconv.Atoi(f[1]); uid >= 500 && !strings.HasPrefix(f[0], "_") {
				local = append(local, map[string]interface{}{"name": f[0], "enabled": true, "admin": admins[f[0]]})
			}
		}
	}
	p["users"] = map[string]interface{}{"local": local}
	firewall := strings.Contains(profileCmd(10*time.Second, socketFilterFW, "--getglobalstate"), "enabled")
	p["security"] = map[string]interface{}{"firewall": []map[string]interface{}{{"profile": "Application firewall", "enabled": firewall}},
		"gatekeeper": strings.Contains(profileCmd(10*time.Second, "spctl", "--status"), "enabled"),
		"sip":        strings.Contains(profileCmd(10*time.Second, "csrutil", "status"), "enabled")}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// startProfile collects and uploads the profile in the background (smartctl and journalctl can take a while).
func (a *Agent) startProfile() {
	if !a.profileBusy.CompareAndSwap(false, true) {
		return
	}
	a.lastProfile = time.Now()
	go func() {
		defer a.profileBusy.Store(false)
		a.sendProfile()
	}()
}

// sendProfile collects and uploads the profile (every 6 hours and on inventory.refresh).
func (a *Agent) sendProfile() {
	if a.client == nil || a.client.DeviceID == "" {
		return
	}
	profile := CollectProfile()
	if err := a.client.do("POST", "/api/v1/devices/"+a.client.DeviceID+"/profile", map[string]interface{}{"profile": profile}, nil, nil); err != nil {
		a.emit("inventory.profile.failed", "rmm", "The system profile could not be sent: "+err.Error(), map[string]interface{}{})
	}
}
