package fleet

// infra.poll: read-only calls to a Proxmox VE or VMware vCenter API on this device's network, for infrastructure
// monitoring when the cloud cannot reach it. The command names only the source; the address and credential come from
// the cloud once, for this command, and are never written to disk. Only the provider's fixed read requests are sent.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// InfraCredential is what the cloud releases for one infra.poll command.
type InfraCredential struct {
	Provider    string `json:"provider"`
	BaseURL     string `json:"baseUrl"`
	TLSInsecure bool   `json:"tlsInsecure"`
	TokenID     string `json:"tokenId"`
	Secret      string `json:"secret"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

// infraAllowLoopback lets tests use a local test server; the agent never sets it.
var infraAllowLoopback = false

const infraMaxBody = 2 << 20
const infraMaxHosts = 50

// FetchInfraCredential asks the cloud for the address and credential of one pending infra.poll command.
func (c *Client) FetchInfraCredential(commandID string) (*InfraCredential, error) {
	var out InfraCredential
	if err := c.do("POST", "/api/v1/devices/"+c.DeviceID+"/commands/"+commandID+"/infra-credential", map[string]string{}, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

func infraBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", errors.New("the source address must be https://host[:port]")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && ((ip.IsLoopback() && !infraAllowLoopback) || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return "", errors.New("not an infrastructure address")
	}
	return "https://" + u.Host, nil
}

// InfraPollContext performs the provider's read requests and returns {"responses": [{name, status, body}|{name, status: 0, error}]}.
func InfraPollContext(ctx context.Context, cred *InfraCredential, client *http.Client) (map[string]interface{}, error) {
	if cred == nil {
		return nil, errors.New("no credential")
	}
	base, err := infraBase(cred.BaseURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cred.TLSInsecure}, //nolint:gosec // self-signed hypervisor certificate, by explicit source setting
			Proxy:           nil,                                               // the server is on this LAN, never behind the web proxy
		}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	var responses []map[string]interface{}
	call := func(name, method, path string, headers map[string]string) (int, []byte) {
		req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
		if err != nil {
			responses = append(responses, map[string]interface{}{"name": name, "status": 0, "error": err.Error()})
			return 0, nil
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			responses = append(responses, map[string]interface{}{"name": name, "status": 0, "error": err.Error()})
			return 0, nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, infraMaxBody))
		if name != "" {
			responses = append(responses, map[string]interface{}{"name": name, "status": resp.StatusCode, "body": string(body)})
		}
		return resp.StatusCode, body
	}
	switch cred.Provider {
	case "proxmox":
		h := map[string]string{"Authorization": "PVEAPIToken=" + cred.TokenID + "=" + cred.Secret}
		for _, r := range [][2]string{{"nodes", "/api2/json/nodes"}, {"vms", "/api2/json/cluster/resources?type=vm"},
			{"storage", "/api2/json/cluster/resources?type=storage"}} {
			if status, _ := call(r[0], "GET", r[1], h); status == 0 || status == 401 || status == 403 {
				break
			}
		}
	case "vsphere":
		basic := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
		status, body := call("", "POST", "/api/session", map[string]string{"Authorization": "Basic " + basic})
		responses = append(responses, map[string]interface{}{"name": "session", "status": status, "body": ""})
		if status < 200 || status >= 300 {
			break
		}
		var session string
		if json.Unmarshal(body, &session) != nil || session == "" {
			responses = append(responses, map[string]interface{}{"name": "session", "status": 0, "error": "vCenter returned no session"})
			break
		}
		h := map[string]string{"vmware-api-session-id": session}
		_, hostsBody := call("hosts", "GET", "/api/vcenter/host", h)
		call("vms", "GET", "/api/vcenter/vm", h)
		call("datastores", "GET", "/api/vcenter/datastore", h)
		var hosts []struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(hostsBody, &hosts) == nil {
			for i, host := range hosts {
				if i >= infraMaxHosts || strings.ContainsAny(host.Host, "/?&#") {
					break
				}
				call("vms-on:"+host.Host, "GET", "/api/vcenter/vm?hosts="+url.QueryEscape(host.Host), h)
			}
		}
		call("", "DELETE", "/api/session", h)
	default:
		return nil, errors.New("unknown infrastructure provider")
	}
	return map[string]interface{}{"responses": responses}, nil
}
