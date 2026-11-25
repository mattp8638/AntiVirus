package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFimScanHashesFilesAndRefusesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("PermitRootLogin no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(dir, "cron.d"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "cron.d", "job"), []byte("* * * * * root true\n"), 0o644)
	payload, _ := json.Marshal(map[string]interface{}{"paths": []string{dir, "relative/path", filepath.Join(dir, "missing")}})
	out, err := FimScanContext(context.Background(), string(payload))
	if err != nil {
		t.Fatal(err)
	}
	files := out["files"].([]map[string]interface{})
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %v", files)
	}
	for _, f := range files {
		if len(f["sha256"].(string)) != 64 {
			t.Fatalf("no hash for %v", f)
		}
	}
	errs := out["errors"].([]string)
	if len(errs) != 1 || !strings.Contains(errs[0], "not an absolute path") {
		t.Fatalf("unexpected errors %v (a missing path is not an error)", errs)
	}
}

func TestContainerPostureFlagsRiskySettings(t *testing.T) {
	oldLook, oldRun := lookPath, runContainerCLI
	defer func() { lookPath, runContainerCLI = oldLook, oldRun }()
	lookPath = func(tool string) (string, error) {
		if tool == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("missing")
	}
	runContainerCLI = func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte("aaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbb\n"), nil
		}
		return []byte(`[{"Id":"aaaaaaaaaaaaaaaa","Name":"/web","Image":"sha256:1","Config":{"Image":"nginx:1.25","User":"101"},
			"HostConfig":{"Privileged":false,"NetworkMode":"bridge"},"Mounts":[]},
			{"Id":"bbbbbbbbbbbbbbbb","Name":"/agent","Image":"sha256:2","Config":{"Image":"tool:latest","User":""},
			"HostConfig":{"Privileged":true,"NetworkMode":"host","PidMode":"host","CapAdd":["SYS_ADMIN"]},
			"Mounts":[{"Source":"/var/run/docker.sock"}]}]`), nil
	}
	out, err := ContainerInventoryContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cs := out["containers"].([]map[string]interface{})
	if out["runtime"] != "docker" || len(cs) != 2 || len(cs[0]["risks"].([]string)) != 0 {
		t.Fatalf("unexpected %v", out)
	}
	risks := strings.Join(cs[1]["risks"].([]string), ",")
	for _, want := range []string{"privileged", "host network", "host PID namespace", "runs as root", "capability SYS_ADMIN", "mounts host /var/run/docker.sock"} {
		if !strings.Contains(risks, want) {
			t.Fatalf("missing risk %q in %s", want, risks)
		}
	}
}
