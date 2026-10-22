package ml

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../../../../ml/testdata"

func TestGoldenFeatures(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "golden-features.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string][]float64
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	for name, want := range golden {
		data, err := os.ReadFile(filepath.Join(testdata, name))
		if err != nil {
			t.Fatal(err)
		}
		got := Extract(data)
		for i := range want {
			if float32(want[i]) != got[i] {
				t.Fatalf("%s feature %d: got %v want %v", name, i, got[i], want[i])
			}
		}
	}
}

func TestMurmurKnownValues(t *testing.T) {
	// From sklearn.utils.murmurhash3_32(..., seed=0)
	cases := map[string]int32{"": 0, "a": 1009084850}
	for in, want := range cases {
		if got := murmur3([]byte(in)); got != want {
			t.Fatalf("murmur3(%q)=%d want %d", in, got, want)
		}
	}
}

func TestNonPE(t *testing.T) {
	v := Extract([]byte("#!/bin/sh\necho hello world\n"))
	if len(v) != Dim || v[616] != 27 || IsPE([]byte("MZ")) {
		t.Fatal("non-PE handling wrong")
	}
}

// TestCorpusParity compares against the Python reference on a directory of PEs.
// Set FENRIR_PE_CORPUS and FENRIR_PY to run it.
func TestCorpusParity(t *testing.T) {
	dir, py := os.Getenv("FENRIR_PE_CORPUS"), os.Getenv("FENRIR_PY")
	if dir == "" || py == "" {
		t.Skip("set FENRIR_PE_CORPUS and FENRIR_PY")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	script := `import sys,json; sys.path.insert(0, sys.argv[1]); from fenrir_ml import features as F
print(json.dumps({p: F.extract(open(p,"rb").read()) for p in sys.argv[2:]}))`
	out, err := exec.Command(py, append([]string{"-c", script, filepath.Join(testdata, "..")}, files...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	var ref map[string][]float64
	if err := json.Unmarshal(out, &ref); err != nil {
		t.Fatal(err)
	}
	bad := 0
	for path, want := range ref {
		data, _ := os.ReadFile(path)
		got := Extract(data)
		for i := range want {
			if float32(want[i]) != got[i] && !(math.IsNaN(want[i]) && math.IsNaN(float64(got[i]))) {
				bad++
				t.Errorf("%s feature %d: got %v want %v", strings.TrimPrefix(path, dir), i, got[i], want[i])
				break
			}
		}
	}
	t.Logf("compared %d files, %d mismatched", len(ref), bad)
}
