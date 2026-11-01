package fleet

// amt.wsman: WS-Management calls to an Intel AMT engine on this device's LAN, for out-of-band power control when the
// cloud cannot reach the engine itself. The command carries only the request bodies; the host, user name and
// password come from the cloud once, for this command, and are never written to disk.

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AmtCredential is what the cloud releases for one amt.wsman command.
type AmtCredential struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TLS         bool   `json:"tls"`
	TLSInsecure bool   `json:"tlsInsecure"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

// FetchAmtCredential asks the cloud for the connection details of one pending amt.wsman command.
func (c *Client) FetchAmtCredential(commandID string) (*AmtCredential, error) {
	var out AmtCredential
	if err := c.do("POST", "/api/v1/devices/"+c.DeviceID+"/commands/"+commandID+"/amt-credential", map[string]string{}, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

type amtRequest struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

// AmtWsmanContext performs the requests in order and returns {"responses": [{name, status, body}|{name, status: 0, error}]}.
func AmtWsmanContext(ctx context.Context, payloadJSON string, cred *AmtCredential, client *http.Client) (map[string]interface{}, error) {
	var p struct {
		Requests []amtRequest `json:"requests"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil || len(p.Requests) == 0 || len(p.Requests) > 10 {
		return nil, errors.New("amt.wsman needs between 1 and 10 requests")
	}
	if cred == nil || (cred.Port != 16992 && cred.Port != 16993) {
		return nil, errors.New("Intel AMT listens on 16992 or 16993 only")
	}
	if ip := net.ParseIP(cred.Host); ip != nil && (ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified()) {
		return nil, errors.New("not an AMT address")
	}
	scheme := "http"
	if cred.Port == 16993 {
		scheme = "https"
	}
	url := scheme + "://" + net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port)) + "/wsman"
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cred.TLSInsecure}, //nolint:gosec // AMT's self-signed certificate, by explicit endpoint setting
			Proxy:           nil,                                               // the engine is on this LAN, never behind the web proxy
		}}
	}
	responses := make([]map[string]interface{}, 0, len(p.Requests))
	for _, r := range p.Requests {
		status, body, err := digestPost(ctx, client, url, cred.Username, cred.Password, []byte(r.Body))
		if err != nil {
			responses = append(responses, map[string]interface{}{"name": r.Name, "status": 0, "error": err.Error()})
			break
		}
		responses = append(responses, map[string]interface{}{"name": r.Name, "status": status, "body": body})
	}
	return map[string]interface{}{"responses": responses}, nil
}

func digestPost(ctx context.Context, client *http.Client, url, user, password string, body []byte) (int, string, error) {
	send := func(auth string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return client.Do(req)
	}
	resp, err := send("")
	if err != nil {
		return 0, "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		auth, err := DigestAuthorization(challenge, "POST", requestURI(url), user, password)
		if err != nil {
			return http.StatusUnauthorized, "", nil
		}
		if resp, err = send(auth); err != nil {
			return 0, "", err
		}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp.StatusCode, string(data), nil
}

func requestURI(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		if j := strings.Index(url[i+3:], "/"); j >= 0 {
			return url[i+3+j:]
		}
	}
	return "/"
}

// DigestAuthorization answers an HTTP Digest challenge (RFC 7616, MD5, qop=auth), as Intel AMT requires.
func DigestAuthorization(challenge, method, uri, user, password string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "digest ") {
		return "", errors.New("not a digest challenge")
	}
	fields := map[string]string{}
	for _, part := range splitChallenge(challenge[len("Digest "):]) {
		if k, v, ok := strings.Cut(part, "="); ok {
			fields[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	realm, nonce := fields["realm"], fields["nonce"]
	if nonce == "" {
		return "", errors.New("digest challenge without a nonce")
	}
	if alg := strings.ToUpper(fields["algorithm"]); alg != "" && alg != "MD5" {
		return "", fmt.Errorf("unsupported digest algorithm %s", alg)
	}
	sum := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) } //nolint:gosec // RFC 2617 digest
	ha1, ha2 := sum(user+":"+realm+":"+password), sum(method+":"+uri)
	header := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s"`, user, realm, nonce, uri)
	if strings.Contains(fields["qop"], "auth") {
		raw := make([]byte, 8)
		_, _ = rand.Read(raw)
		cnonce, nc := hex.EncodeToString(raw), "00000001"
		header += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s", response="%s"`, nc, cnonce, sum(ha1+":"+nonce+":"+nc+":"+cnonce+":auth:"+ha2))
	} else {
		header += fmt.Sprintf(`, response="%s"`, sum(ha1+":"+nonce+":"+ha2))
	}
	if opaque := fields["opaque"]; opaque != "" {
		header += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	return header + `, algorithm=MD5`, nil
}

// splitChallenge splits on commas outside quotes.
func splitChallenge(s string) []string {
	var parts []string
	inQuote, start := false, 0
	for i, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// intersectPorts keeps the ports both the session and this device's own policy allow (the policy default when unset).
func intersectPorts(session []int, policy []string) []int {
	allowed := map[int]bool{}
	if len(policy) == 0 {
		for _, p := range []int{22, 23, 80, 443, 3389, 5900, 8080, 8443, 16992, 16993, 16994, 16995} {
			allowed[p] = true
		}
	}
	for _, p := range policy {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			allowed[n] = true
		}
	}
	var out []int
	for _, p := range session {
		if allowed[p] {
			out = append(out, p)
		}
	}
	return out
}
