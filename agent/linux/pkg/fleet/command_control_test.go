package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestCancellationStopsScriptChildrenAndReplaysReceiptAfterRetirement(t *testing.T) {
	dir := t.TempDir()
	childFile := filepath.Join(dir, "child.pid")
	var completeCalls atomic.Int32
	var retired atomic.Bool
	var acknowledged atomic.Bool
	script, _ := json.Marshal(map[string]interface{}{
		"language": "sh", "body": "sleep 30 &\necho $! > '" + childFile + "'\nwait\n", "timeoutSeconds": 60,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Device-Api-Key") != "device-key" {
			w.WriteHeader(401)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/state"):
			_, err := os.Stat(childFile)
			requested := err == nil
			status := "dispatched"
			if requested {
				status = "cancelling"
			}
			json.NewEncoder(w).Encode(CommandState{Status: status, CancelRequested: requested})
		case strings.HasSuffix(r.URL.Path, "/commands/pending"):
			if retired.Load() {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"items": []Command{{ID: "cmd_stop", Type: "script.run", PayloadJSON: string(script)}}})
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var body struct {
				Status string `json:"status"`
				Result string `json:"resultJson"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Status != "cancelled" || !strings.Contains(body.Result, "stopConfirmed") {
				t.Errorf("incorrect stop result: %+v", body)
			}
			if completeCalls.Add(1) == 1 {
				retired.Store(true)
				w.WriteHeader(503) // endpoint stopped; first acknowledgement was lost
				return
			}
			acknowledged.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
		default:
			json.NewEncoder(w).Encode(map[string]int{"accepted": 1})
		}
	}))
	defer server.Close()
	agent := New(Config{Server: server.URL, StateDir: dir})
	agent.client.DeviceID, agent.client.APIKey = "dev_stop", "device-key"
	started := time.Now()
	agent.RunCommands()
	if time.Since(started) > 8*time.Second {
		t.Fatal("cancellation did not interrupt the running script")
	}
	raw, err := os.ReadFile(childFile)
	if err != nil {
		t.Fatal("the script did not create a real child process", err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if pid <= 0 {
		t.Fatal("invalid child pid")
	}
	// A killed, unreaped orphan may remain a zombie under a container's PID 1;
	// it cannot run or retain the job's pipes.
	if err := syscall.Kill(pid, 0); err == nil {
		state, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if readErr == nil && !strings.Contains(string(state), ") Z ") {
			t.Fatalf("child %d survived cancellation", pid)
		}
	}
	receipt, found, err := agent.loadCommandReceipt("cmd_stop")
	if err != nil || !found || receipt.Status != "cancelled" {
		t.Fatalf("lost durable cancellation receipt: %+v %v", receipt, err)
	}
	restarted := New(Config{Server: server.URL, StateDir: dir})
	restarted.client.DeviceID, restarted.client.APIKey = "dev_stop", "device-key"
	restarted.RunCommands() // scoped ack works although general polling is now revoked
	if !acknowledged.Load() {
		t.Fatal("retirement prevented cancellation acknowledgement")
	}
	receipt, _, _ = restarted.loadCommandReceipt("cmd_stop")
	if receipt.Status != "cancelled_ack" {
		t.Fatalf("acknowledgement was not persisted: %+v", receipt)
	}
}

func TestCancelledBatchItemNeverStarts(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "should-not-exist")
	payload, _ := json.Marshal(map[string]interface{}{"language": "sh", "body": "touch '" + marker + "'"})
	var confirmed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commands/pending"):
			json.NewEncoder(w).Encode(map[string]interface{}{"items": []Command{{ID: "cmd_queued", Type: "script.run", PayloadJSON: string(payload)}}})
		case strings.HasSuffix(r.URL.Path, "/state"):
			json.NewEncoder(w).Encode(CommandState{Status: "cancelling", CancelRequested: true})
		case strings.HasSuffix(r.URL.Path, "/complete"):
			confirmed.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
		default:
			json.NewEncoder(w).Encode(map[string]int{"accepted": 1})
		}
	}))
	defer server.Close()
	a := New(Config{Server: server.URL, StateDir: dir})
	a.client.DeviceID = "dev_queued"
	a.RunCommands()
	if !confirmed.Load() {
		t.Fatal("cancelled batch entry was not acknowledged")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("cancelled batch entry performed a side effect")
	}
}

func TestCancelledScanDoesNotReadOrQuarantineFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(filepath.Join(root, "quarantine"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanned, findings := scanner.ScanPathsWith([]string{root}, nil, true, 0, ScanOptions{Context: ctx})
	if scanned != 0 || len(findings) != 0 {
		t.Fatal("cancelled scan continued")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("cancelled scan removed a file")
	}
}
