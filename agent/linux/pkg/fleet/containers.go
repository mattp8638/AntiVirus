package fleet

// container.inventory: the containers on this host, read from the Docker or Podman command-line tools (whichever is
// installed), with the runtime settings that matter for security: privileged mode, host network or PID namespace,
// running as root, sensitive host paths mounted, and added capabilities. Read-only: nothing is started or stopped.

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

var containerRuntimes = []string{"docker", "podman"}

// runContainerCLI is replaced in tests.
var runContainerCLI = func(ctx context.Context, tool string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, tool, args...).Output()
}

var lookPath = exec.LookPath

var sensitiveMounts = []string{"/", "/etc", "/root", "/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock", "/proc", "/sys", "/dev", "/boot"}

// ContainerInventoryContext returns {"runtime": name|"", "containers": [...]}.
func ContainerInventoryContext(ctx context.Context) (map[string]interface{}, error) {
	for _, tool := range containerRuntimes {
		if _, err := lookPath(tool); err != nil {
			continue
		}
		ids, err := runContainerCLI(ctx, tool, "ps", "-q", "--no-trunc")
		if err != nil {
			return map[string]interface{}{"runtime": tool, "containers": []interface{}{}, "error": "the " + tool + " daemon did not answer"}, nil
		}
		list := strings.Fields(string(ids))
		if len(list) > 200 {
			list = list[:200]
		}
		containers := []map[string]interface{}{}
		if len(list) > 0 {
			raw, err := runContainerCLI(ctx, tool, append([]string{"inspect"}, list...)...)
			if err != nil {
				return nil, errors.New(tool + " inspect failed")
			}
			var details []map[string]interface{}
			if err := json.Unmarshal(raw, &details); err != nil {
				return nil, errors.New("could not read " + tool + " inspect output")
			}
			for _, d := range details {
				containers = append(containers, containerPosture(d))
			}
		}
		return map[string]interface{}{"runtime": tool, "containers": containers}, nil
	}
	return map[string]interface{}{"runtime": "", "containers": []interface{}{}}, nil
}

func inspectField(m map[string]interface{}, keys ...string) interface{} {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func containerPosture(d map[string]interface{}) map[string]interface{} {
	name, _ := d["Name"].(string)
	image, _ := inspectField(d, "Config", "Image").(string)
	user, _ := inspectField(d, "Config", "User").(string)
	privileged, _ := inspectField(d, "HostConfig", "Privileged").(bool)
	network, _ := inspectField(d, "HostConfig", "NetworkMode").(string)
	pid, _ := inspectField(d, "HostConfig", "PidMode").(string)
	risks := []string{}
	if privileged {
		risks = append(risks, "privileged")
	}
	if network == "host" {
		risks = append(risks, "host network")
	}
	if pid == "host" {
		risks = append(risks, "host PID namespace")
	}
	if user == "" || user == "root" || user == "0" || strings.HasPrefix(user, "0:") {
		risks = append(risks, "runs as root")
	}
	if caps, ok := inspectField(d, "HostConfig", "CapAdd").([]interface{}); ok {
		for _, c := range caps {
			if s, _ := c.(string); s == "SYS_ADMIN" || s == "CAP_SYS_ADMIN" || s == "ALL" || s == "NET_ADMIN" || s == "SYS_PTRACE" {
				risks = append(risks, "capability "+s)
			}
		}
	}
	mounts := []string{}
	if ms, ok := d["Mounts"].([]interface{}); ok {
		for _, m := range ms {
			mm, _ := m.(map[string]interface{})
			src, _ := mm["Source"].(string)
			for _, s := range sensitiveMounts {
				if src == s {
					risks = append(risks, "mounts host "+src)
				}
			}
			mounts = append(mounts, src)
		}
	}
	id, _ := d["Id"].(string)
	if len(id) > 12 {
		id = id[:12]
	}
	return map[string]interface{}{"id": id, "name": strings.TrimPrefix(name, "/"), "image": image, "imageId": d["Image"],
		"user": user, "risks": risks, "mounts": mounts, "started": inspectField(d, "State", "StartedAt")}
}
