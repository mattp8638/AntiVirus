package fleet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommandReceiptsSurviveNewAgentAndPreserveResult(t *testing.T) {
	dir := t.TempDir()
	first := New(Config{StateDir: dir})
	if err := first.saveCommandReceipt("cmd_receipt_01", "started", nil); err != nil {
		t.Fatal(err)
	}
	pending, exists, err := New(Config{StateDir: dir}).loadCommandReceipt("cmd_receipt_01")
	if err != nil || !exists || pending.Status != "started" {
		t.Fatalf("inflight record: %#v %v", pending, err)
	}
	expected := map[string]interface{}{"exitCode": float64(0), "stdout": "ok"}
	if err := first.saveCommandReceipt("cmd_receipt_01", "completed", expected); err != nil {
		t.Fatal(err)
	}
	saved, exists, err := New(Config{StateDir: dir}).loadCommandReceipt("cmd_receipt_01")
	if err != nil || !exists || saved.Status != "completed" || saved.Result["stdout"] != "ok" {
		t.Fatalf("reloaded command result: %#v %v", saved, err)
	}
	info, err := os.Stat(filepath.Join(dir, "command-receipts", "cmd_receipt_01.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("command result leaked to other users: %v", info.Mode().Perm())
	}
}

func TestCommandReceiptNeverAcceptsPathTraversalOrCorruptState(t *testing.T) {
	agent := New(Config{StateDir: t.TempDir()})
	for _, id := range []string{"../state", "/etc/passwd", "a/b", "", "."} {
		if err := agent.saveCommandReceipt(id, "started", nil); err == nil {
			t.Fatalf("accepted unsafe command identifier %q", id)
		}
	}
	if err := agent.saveCommandReceipt("cmd_valid", "unexpected", nil); err == nil {
		t.Fatal("accepted invalid state")
	}
	if _, exists, err := agent.loadCommandReceipt("cmd_missing"); exists || err != nil {
		t.Fatalf("expected missing receipt: %v", err)
	}
	filename, err := agent.receiptPath("cmd_corrupt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := agent.loadCommandReceipt("cmd_corrupt"); exists || err == nil {
		t.Fatalf("corrupt receipt must block automatic command replay: exists=%v error=%v", exists, err)
	}
}
