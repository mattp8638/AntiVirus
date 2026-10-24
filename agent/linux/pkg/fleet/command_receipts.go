package fleet

import (
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "regexp"
)

var commandIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

type commandReceipt struct {
    Status string                 `json:"status"`
    Result map[string]interface{} `json:"result"`
}

// A receipt is written before executing a remote command, then replaced with
// its final outcome before talking to the cloud. If a process crashes after
// execution but before reporting, the next poll sends the locally stored
// result instead of repeating an action with side effects.
func (a *Agent) receiptPath(id string) (string, error) {
    if !commandIDPattern.MatchString(id) {
        return "", errors.New("invalid server command identifier")
    }
    return filepath.Join(a.cfg.StateDir, "command-receipts", id+".json"), nil
}

func (a *Agent) loadCommandReceipt(id string) (commandReceipt, bool, error) {
    path, err := a.receiptPath(id)
    if err != nil { return commandReceipt{}, false, err }
    data, err := os.ReadFile(path)
    if errors.Is(err, os.ErrNotExist) { return commandReceipt{}, false, nil }
    if err != nil { return commandReceipt{}, false, err }
    var r commandReceipt
    if err := json.Unmarshal(data, &r); err != nil { return commandReceipt{}, false, err }
    if r.Status != "started" && r.Status != "completed" && r.Status != "failed" {
        return commandReceipt{}, false, errors.New("invalid stored command state")
    }
    return r, true, nil
}

func (a *Agent) saveCommandReceipt(id, status string, result map[string]interface{}) error {
    if status != "started" && status != "completed" && status != "failed" {
        return errors.New("invalid command receipt status")
    }
    path, err := a.receiptPath(id)
    if err != nil { return err }
    if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { return err }
    data, err := json.Marshal(commandReceipt{Status:status, Result:result})
    if err != nil { return err }
    file, err := os.CreateTemp(filepath.Dir(path), ".receipt-*")
    if err != nil { return err }
    defer os.Remove(file.Name())
    if err := file.Chmod(0o600); err != nil { file.Close(); return err }
    if _, err := file.Write(data); err != nil { file.Close(); return err }
    if err := file.Sync(); err != nil { file.Close(); return err }
    if err := file.Close(); err != nil { return err }
    if err := os.Rename(file.Name(),path); err != nil { return err }
    dir, err := os.Open(filepath.Dir(path))
    if err != nil { return err }
    defer dir.Close()
    if err := dir.Sync(); err != nil { return fmt.Errorf("could not persist command receipt directory: %w",err) }
    return nil
}
