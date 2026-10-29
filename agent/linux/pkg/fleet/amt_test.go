package fleet

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestAmtWsmanUsesDigestAuthAndOnlyAmtPorts(t *testing.T) {
	const realm, password = "Digest:AMT", "Amt-P4ss!"
	md := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		f := map[string]string{}
		for _, m := range regexp.MustCompile(`(\w+)="?([^",]+)"?`).FindAllStringSubmatch(strings.TrimPrefix(auth, "Digest "), -1) {
			f[m[1]] = m[2]
		}
		want := md(md(f["username"]+":"+realm+":"+password) + ":" + f["nonce"] + ":" + f["nc"] + ":" + f["cnonce"] + ":auth:" + md("POST:"+f["uri"]))
		if f["response"] == "" || f["response"] != want || f["uri"] != "/wsman" {
			w.Header().Set("WWW-Authenticate", `Digest realm="`+realm+`", nonce="abc", qop="auth"`)
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		_, _ = w.Write([]byte("<ok/>"))
	}))
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}}
	payload := `{"requests":[{"name":"identify","body":"<Identify/>"},{"name":"power","body":"<Enumerate/>"}]}`
	cred := &AmtCredential{Host: "192.168.10.21", Port: 16992, Username: "admin", Password: password}
	out, err := AmtWsmanContext(context.Background(), payload, cred, client)
	if err != nil {
		t.Fatal(err)
	}
	responses := out["responses"].([]map[string]interface{})
	if len(responses) != 2 || responses[0]["status"] != 200 || responses[1]["body"] != "<ok/>" || len(bodies) != 2 {
		t.Fatalf("responses %v bodies %v", responses, bodies)
	}
	cred.Password = "wrong"
	out, _ = AmtWsmanContext(context.Background(), payload, cred, client)
	if out["responses"].([]map[string]interface{})[0]["status"] != 401 {
		t.Fatalf("a wrong password must come back as 401: %v", out)
	}
	cred.Port = 22
	if _, err := AmtWsmanContext(context.Background(), payload, cred, client); err == nil {
		t.Fatal("only the AMT ports may be used, so the credential cannot be sent to another service")
	}
}

func TestIntersectPorts(t *testing.T) {
	if got := intersectPorts([]int{22, 3389, 445}, []string{"3389", " 22"}); len(got) != 2 || got[0] != 22 || got[1] != 3389 {
		t.Fatalf("got %v", got)
	}
	if got := intersectPorts([]int{3389, 445}, nil); len(got) != 1 || got[0] != 3389 {
		t.Fatalf("defaults: %v", got)
	}
}
