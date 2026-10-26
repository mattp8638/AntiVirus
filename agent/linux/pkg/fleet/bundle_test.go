package fleet

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildAndUploadBundle(t *testing.T) {
	read := func(path string) ([]byte, error) {
		switch path {
		case "/etc/crontab":
			return []byte("* * * * * root evil"), nil
		case "/etc/huge":
			return make([]byte, maxBundleFile+1), nil
		}
		return nil, errors.New("permission denied")
	}
	data, err := BuildBundle(map[string]interface{}{"agentVersion": "1"}, []string{"/etc/huge", "/etc/crontab", "/root/secret"}, read)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	contents := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		contents[h.Name] = string(body)
	}
	if !strings.Contains(contents["triage.json"], `"agentVersion": "1"`) || contents["files/etc/crontab"] != "* * * * * root evil" {
		t.Fatalf("bundle: %v", contents)
	}
	if !strings.Contains(contents["skipped.txt"], "/etc/huge: too large") || !strings.Contains(contents["skipped.txt"], "permission denied") {
		t.Fatalf("skipped: %q", contents["skipped.txt"])
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices/dev1/commands/cmd1/artifact" || r.Header.Get("X-Device-Api-Key") != "key" ||
			r.URL.Query().Get("sha256") == "" || r.URL.Query().Get("filename") != "b.tar.gz" {
			w.WriteHeader(400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, data) {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"artifactId":"art_1"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL)
	client.DeviceID, client.APIKey = "dev1", "key"
	id, err := client.UploadArtifact("cmd1", "b.tar.gz", data)
	if err != nil || id != "art_1" {
		t.Fatalf("upload: %v %v", id, err)
	}
	if _, err := client.UploadArtifact("other", "b.tar.gz", data); err == nil {
		t.Fatal("errors must surface")
	}
}
