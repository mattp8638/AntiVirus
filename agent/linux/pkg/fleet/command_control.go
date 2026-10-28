package fleet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type CommandState struct {
	Status          string `json:"status"`
	CancelRequested bool   `json:"cancelRequested"`
}

func (c *Client) CommandState(ctx context.Context, id string) (CommandState, error) {
	var state CommandState
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := c.doContext(ctx, "GET", "/api/v1/devices/"+c.DeviceID+"/commands/"+id+"/state", nil, &state, nil)
	var failure *APIError
	if errors.As(err, &failure) && (failure.Status == 401 || failure.Status == 403 || failure.Status == 404) {
		return CommandState{Status: "cancelled", CancelRequested: true}, nil
	}
	if err == nil && state.Status == "" {
		err = fmt.Errorf("command state was missing")
	}
	return state, err
}

// One cancellation context owns one action, not the agent or unrelated background work.
// Receipt persistence and acknowledgement happen only after ExecuteContext has returned.
func (a *Agent) executeControlled(cmd Command) (map[string]interface{}, string, error) {
	state, err := a.client.CommandState(context.Background(), cmd.ID)
	if err != nil {
		return nil, "failed", err
	}
	if state.CancelRequested || (state.Status != "pending" && state.Status != "dispatched") {
		return map[string]interface{}{"cancelledBeforeExecution": true, "stopConfirmed": true}, "cancelled", nil
	}
	ctx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	watch, stopWatch := context.WithCancel(context.Background())
	var requested atomic.Bool
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		timer := time.NewTicker(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-watch.Done():
				return
			case <-a.stop:
				cancelWork()
				return
			case <-timer.C:
				state, err := a.client.CommandState(watch, cmd.ID)
				if err == nil && state.CancelRequested {
					requested.Store(true)
					cancelWork()
					return
				}
				// Network loss leaves cancellation unconfirmed in the console.
			}
		}
	}()
	result, err := a.ExecuteContext(ctx, cmd)
	stopWatch()
	<-finished
	if requested.Load() {
		if result == nil {
			result = map[string]interface{}{}
		}
		result["cancelled"], result["stopConfirmed"] = true, true
		return result, "cancelled", err
	}
	return result, "completed", err
}

// A decommissioned endpoint cannot poll for work. Its scoped key can still
// acknowledge its own cancellation, including after a lost response/restart.
func (a *Agent) replayCancellationReceipts() {
	entries, err := os.ReadDir(filepath.Join(a.cfg.StateDir, "command-receipts"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		receipt, found, err := a.loadCommandReceipt(id)
		if err != nil || !found || receipt.Status != "cancelled" {
			continue
		}
		if a.client.CompleteCommand(id, "cancelled", receipt.Result) == nil {
			_ = a.saveCommandReceipt(id, "cancelled_ack", receipt.Result)
		}
	}
}
