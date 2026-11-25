package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInfraPollVsphereSendsOnlyReadRequests(t *testing.T) {
	infraAllowLoopback = true
	defer func() { infraAllowLoopback = false }()
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.URL.Path == "/api/session" && r.Method == "POST":
			if u, p, ok := r.BasicAuth(); !ok || u != "ro" || p != "pw" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`"sess"`))
		case r.Header.Get("vmware-api-session-id") != "sess":
			w.WriteHeader(401)
		case r.URL.Path == "/api/vcenter/host":
			_, _ = w.Write([]byte(`[{"host":"host-1","name":"esx1","connection_state":"CONNECTED"}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()
	out, err := InfraPollContext(context.Background(), &InfraCredential{Provider: "vsphere", BaseURL: srv.URL, Username: "ro", Password: "pw"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	responses := out["responses"].([]map[string]interface{})
	names := []string{}
	for _, r := range responses {
		names = append(names, r["name"].(string))
	}
	if strings.Join(names, ",") != "session,hosts,vms,datastores,vms-on:host-1" {
		t.Fatalf("unexpected responses %v", names)
	}
	for _, s := range seen {
		if !strings.HasPrefix(s, "GET ") && s != "POST /api/session" && s != "DELETE /api/session" {
			t.Fatalf("a request that is not a read: %s", s)
		}
	}
}

func TestInfraPollProxmoxStopsOnAuthFailureAndRejectsBadAddresses(t *testing.T) {
	infraAllowLoopback = true
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "PVEAPIToken=a@pve!x=s" {
			t.Fatalf("wrong token header %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	out, err := InfraPollContext(context.Background(), &InfraCredential{Provider: "proxmox", BaseURL: srv.URL, TokenID: "a@pve!x", Secret: "s"}, srv.Client())
	if err != nil || calls != 1 || len(out["responses"].([]map[string]interface{})) != 1 {
		t.Fatalf("expected one refused call, got %d calls, err %v", calls, err)
	}
	infraAllowLoopback = false
	for _, bad := range []string{"http://pve.lan:8006", "https://127.0.0.1:8006", "https://pve.lan/api?x=1", "https://u:p@pve.lan"} {
		if _, err := InfraPollContext(context.Background(), &InfraCredential{Provider: "proxmox", BaseURL: bad}, nil); err == nil {
			t.Fatalf("address %s should be refused", bad)
		}
	}
}
