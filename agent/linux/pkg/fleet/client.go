// Package fleet implements the Fenrir Cloud agent protocol: enrollment,
// heartbeat, policy check-in, telemetry upload and the remote command queue.
// It mirrors agent/windows/service/src/ControlPlaneClient.cpp so every agent
// talks to the cloud the same way.
package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to Fenrir Cloud. DeviceID/APIKey are empty until enrollment.
type Client struct {
	BaseURL  string
	DeviceID string
	APIKey   string
	HTTP     *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/api/v1"), "/"),
		HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type EnrollRequest struct {
	Hostname        string `json:"hostname"`
	OSVersion       string `json:"osVersion"`
	SerialNumber    string `json:"serialNumber"`
	Platform        string `json:"platform"`
	AgentVersion    string `json:"agentVersion"`
	EnrollmentToken string `json:"enrollmentToken,omitempty"`
}

type EnrollResponse struct {
	DeviceID          string `json:"deviceId"`
	TenantID          string `json:"tenantId"`
	DeviceAPIKey      string `json:"deviceApiKey"`
	Approved          bool   `json:"approved"`
	DNSOverHTTPSURL   string `json:"dnsOverHttpsUrl"`
	CommandChannelURL string `json:"commandChannelUrl"`
	Policy            Policy `json:"policy"`
}

// Policy is the agent policy document. Only what this agent enforces is typed;
// the rest stays in Modules for forward compatibility.
type Policy struct {
	ID                          string                            `json:"id"`
	Name                        string                            `json:"name"`
	Revision                    string                            `json:"revision"`
	RealtimeProtection          bool                              `json:"realtimeProtection"`
	CloudLookup                 bool                              `json:"cloudLookup"`
	QuarantineOnMalicious       bool                              `json:"quarantineOnMalicious"`
	NetworkContainment          bool                              `json:"networkContainment"`
	EnforceProcessStartVerdicts bool                              `json:"enforceProcessStartVerdicts"`
	TerminateProcessTreeOnBlock bool                              `json:"terminateProcessTreeOnExecuteBlock"`
	SuppressionPathRoots        []string                          `json:"suppressionPathRoots"`
	SuppressionSha256           []string                          `json:"suppressionSha256"`
	Modules                     map[string]map[string]interface{} `json:"modules"`
}

// ModuleBool reads modules.<section>.<key> as a bool with a default.
func (p Policy) ModuleBool(section, key string, def bool) bool {
	if v, ok := p.Modules[section][key].(bool); ok {
		return v
	}
	return def
}

func (p Policy) ModuleInt(section, key string, def int) int {
	if v, ok := p.Modules[section][key].(float64); ok {
		return int(v)
	}
	return def
}

func (p Policy) ModuleStrings(section, key string) []string {
	raw, _ := p.Modules[section][key].([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

type Event struct {
	EventID     string `json:"eventId"`
	EventType   string `json:"eventType"`
	Source      string `json:"source"`
	Summary     string `json:"summary"`
	OccurredAt  string `json:"occurredAt"`
	PayloadJSON string `json:"payloadJson"`
}

type Command struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	IssuedBy    string `json:"issuedBy"`
	TargetPath  string `json:"targetPath"`
	RecordID    string `json:"recordId"`
	PayloadJSON string `json:"payloadJson"`
}

type Bundle struct {
	SignatureVersion string `json:"signatureVersion"`
	Hashes           []struct {
		Type          string `json:"type"`
		Value         string `json:"value"`
		MalwareFamily string `json:"malwareFamily"`
	} `json:"hashes"`
	AllowSha256 []string `json:"allowSha256"`
}

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("fenrir cloud returned %d: %s", e.Status, e.Body)
}

func (c *Client) do(method, path string, body, out interface{}, headers map[string]string) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("X-Device-Api-Key", c.APIKey)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Enroll(req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	headers := map[string]string{}
	if req.EnrollmentToken != "" {
		headers["X-Fenrir-Token"] = req.EnrollmentToken
	}
	if err := c.do("POST", "/api/v1/enroll", req, &out, headers); err != nil {
		return nil, err
	}
	c.DeviceID, c.APIKey = out.DeviceID, out.DeviceAPIKey
	return &out, nil
}

type HeartbeatResponse struct {
	EffectivePolicyRevision string `json:"effectivePolicyRevision"`
	CommandsPending         int    `json:"commandsPending"`
	Approved                bool   `json:"approved"`
}

func (c *Client) Heartbeat(agentVersion, health string, isolated bool, metrics map[string]interface{}) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	body := map[string]interface{}{"agentVersion": agentVersion, "platformVersion": agentVersion, "healthState": health, "isolated": isolated}
	if metrics != nil {
		body["metrics"] = metrics
	}
	return &out, c.do("POST", "/api/v1/devices/"+c.DeviceID+"/heartbeat", body, &out, nil)
}

func (c *Client) PolicyCheckIn(revision, agentVersion string) (Policy, bool, error) {
	var out struct {
		Changed bool   `json:"changed"`
		Policy  Policy `json:"policy"`
	}
	body := map[string]string{"currentPolicyRevision": revision, "agentVersion": agentVersion, "platformVersion": agentVersion}
	err := c.do("POST", "/api/v1/devices/"+c.DeviceID+"/policy-check-in", body, &out, nil)
	return out.Policy, out.Changed, err
}

func (c *Client) SendTelemetry(events []Event) (int, error) {
	var out struct {
		Accepted int `json:"accepted"`
	}
	err := c.do("POST", "/api/v1/devices/"+c.DeviceID+"/telemetry", map[string]interface{}{"events": events}, &out, nil)
	return out.Accepted, err
}

func (c *Client) PendingCommands(limit int) ([]Command, error) {
	var out struct {
		Items []Command `json:"items"`
	}
	err := c.do("GET", fmt.Sprintf("/api/v1/devices/%s/commands/pending?limit=%d", c.DeviceID, limit), nil, &out, nil)
	return out.Items, err
}

func (c *Client) CompleteCommand(id, status string, result interface{}) error {
	data, _ := json.Marshal(result)
	return c.do("POST", "/api/v1/devices/"+c.DeviceID+"/commands/"+id+"/complete",
		map[string]string{"status": status, "resultJson": string(data)}, nil, nil)
}

type ModelManifest struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func (c *Client) FetchModelManifest() (*ModelManifest, error) {
	var out ModelManifest
	return &out, c.do("GET", "/api/v1/agent/model/manifest", nil, &out, nil)
}

// DownloadModel fetches the JSON (gzipped) model, which the Go evaluator reads.
func (c *Client) DownloadModel() ([]byte, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/v1/agent/model?format=json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Device-Api-Key", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &APIError{Status: resp.StatusCode, Body: string(data)}
	}
	return data, nil
}

func (c *Client) FetchBundle() (*Bundle, error) {
	var out Bundle
	return &out, c.do("GET", "/api/v1/agent/bundle?hashesLimit=200000&urlsLimit=0&rulesLimit=0", nil, &out, nil)
}
