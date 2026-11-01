package fleet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// keyServer issues "fdk_new_key_0000000000" from rotate-key and records the key each request carried.
func keyServer(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+r.Header.Get("X-Device-Api-Key"))
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/rotate-key") {
			json.NewEncoder(w).Encode(map[string]string{"deviceApiKey": "fdk_new_key_0000000000"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"rotateKey": true, "commandsPending": 0})
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestRotateKeySavesTheNewKeyBeforeUsingIt(t *testing.T) {
	srv, seen := keyServer(t)
	dir := t.TempDir()
	a := New(Config{Server: srv.URL, StateDir: dir})
	a.state = State{DeviceID: "dev_1", APIKey: "fdk_old_key_0000000000"}
	a.client.DeviceID = "dev_1"
	a.client.SetKey("fdk_old_key_0000000000")

	resp, err := a.client.Heartbeat(Version, "healthy", false, nil)
	if err != nil || !resp.RotateKey {
		t.Fatalf("heartbeat did not carry rotateKey: %v %+v", err, resp)
	}
	a.rotateKey()

	if (*seen)[1] != "/api/v1/devices/dev_1/rotate-key fdk_old_key_0000000000" {
		t.Fatalf("rotation must be asked for with the current key, got %q", (*seen)[1])
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved State
	json.Unmarshal(data, &saved)
	if saved.APIKey != "fdk_new_key_0000000000" || saved.DeviceID != "dev_1" {
		t.Fatalf("new key not saved: %+v", saved)
	}
	if a.client.Key() != "fdk_new_key_0000000000" || a.state.APIKey != "fdk_new_key_0000000000" {
		t.Fatal("agent did not switch to the new key")
	}
	if _, err := a.client.Heartbeat(Version, "healthy", false, nil); err != nil {
		t.Fatal(err)
	}
	if last := (*seen)[len(*seen)-1]; !strings.HasSuffix(last, "fdk_new_key_0000000000") {
		t.Fatalf("next request did not use the new key: %q", last)
	}
}

func TestRotateKeyKeepsTheOldKeyWhenItCannotBeSaved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read-only directory")
	}
	srv, _ := keyServer(t)
	dir := t.TempDir()
	a := New(Config{Server: srv.URL, StateDir: dir})
	a.state = State{DeviceID: "dev_1", APIKey: "fdk_old_key_0000000000"}
	a.client.DeviceID = "dev_1"
	a.client.SetKey("fdk_old_key_0000000000")
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	a.rotateKey()
	if a.client.Key() != "fdk_old_key_0000000000" || a.state.APIKey != "fdk_old_key_0000000000" {
		t.Fatal("an unsaved key must never be used: the agent would lose its identity on restart")
	}
}

func TestRotateKeyKeepsTheOldKeyWhenTheServerRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"decommissioned devices have no key to rotate"}`, http.StatusConflict)
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := New(Config{Server: srv.URL, StateDir: dir})
	a.state = State{DeviceID: "dev_1", APIKey: "fdk_old_key_0000000000"}
	a.client.DeviceID = "dev_1"
	a.client.SetKey("fdk_old_key_0000000000")
	a.rotateKey()
	if a.client.Key() != "fdk_old_key_0000000000" {
		t.Fatal("key changed after a refused rotation")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatal("state rewritten after a refused rotation")
	}
}

func TestTelemetrySpoolSurvivesARestartWhileOffline(t *testing.T) {
	up := false
	var mu sync.Mutex
	received := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !up {
			http.Error(w, "offline", http.StatusBadGateway)
			return
		}
		var body struct {
			Events []Event `json:"events"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		received += len(body.Events)
		json.NewEncoder(w).Encode(map[string]int{"accepted": len(body.Events)})
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := New(Config{Server: srv.URL, StateDir: dir})
	a.client.DeviceID = "dev_1"
	a.emit("alert.raised", "scanner", "a detection while offline", map[string]interface{}{"n": 1})
	a.emit("alert.raised", "scanner", "another", map[string]interface{}{"n": 2})
	if err := a.flushOrSpool(true); err == nil {
		t.Fatal("upload should fail while offline")
	}
	if _, err := os.Stat(filepath.Join(dir, "telemetry-spool.json")); err != nil {
		t.Fatalf("queue not spooled to disk: %v", err)
	}

	// The agent restarts (the queue in memory is gone) and the cloud comes back.
	b := New(Config{Server: srv.URL, StateDir: dir})
	b.client.DeviceID = "dev_1"
	if n := b.loadSpool(); n != 2 {
		t.Fatalf("reloaded %d events, want 2", n)
	}
	mu.Lock()
	up = true
	mu.Unlock()
	if err := b.flushOrSpool(false); err != nil {
		t.Fatal(err)
	}
	if received != 2 {
		t.Fatalf("server received %d events, want 2", received)
	}
	if _, err := os.Stat(filepath.Join(dir, "telemetry-spool.json")); !os.IsNotExist(err) {
		t.Fatal("spool not removed after the queue drained")
	}
}
