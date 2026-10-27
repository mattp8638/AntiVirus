package fleet

import (
	"encoding/json"
	"testing"
)

func TestCollectProfileHasSections(t *testing.T) {
	if IsMacOS {
		t.Skip("covered on macOS separately")
	}
	p := CollectProfile()
	for _, key := range []string{"collectedAt", "hardware", "os", "volumes", "users", "network", "battery", "security", "events", "services"} {
		if _, ok := p[key]; !ok {
			t.Errorf("missing section %s", key)
		}
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 100 {
		t.Fatalf("profile too small: %s", data)
	}
	t.Logf("%s", data)
}
