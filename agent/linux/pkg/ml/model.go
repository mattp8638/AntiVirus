package ml

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
)

type tree struct {
	F []int32   `json:"f"`
	T []float64 `json:"t"`
	L []int32   `json:"l"`
	R []int32   `json:"r"`
	V []float64 `json:"v"`
}

// Model is a fenrir-gbdt-1 gradient-boosted tree ensemble.
type Model struct {
	Format      string             `json:"format"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	NumFeatures int                `json:"numFeatures"`
	Trees       []tree             `json:"trees"`
	Thresholds  map[string]float64 `json:"thresholds"`
}

// LoadModel reads a model from JSON (optionally gzip-compressed).
func LoadModel(raw []byte) (*Model, error) {
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		if raw, err = io.ReadAll(io.LimitReader(zr, 512<<20)); err != nil {
			return nil, err
		}
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Format != "fenrir-gbdt-1" || m.NumFeatures != Dim {
		return nil, errors.New("unsupported model format")
	}
	for _, t := range m.Trees {
		n := len(t.F)
		if len(t.T) != n || len(t.L) != n || len(t.R) != n || len(t.V) == 0 {
			return nil, errors.New("malformed tree")
		}
		for i := 0; i < n; i++ {
			if t.F[i] < 0 || int(t.F[i]) >= Dim || !validChild(t.L[i], n, len(t.V)) || !validChild(t.R[i], n, len(t.V)) {
				return nil, errors.New("malformed tree node")
			}
		}
	}
	return &m, nil
}

func validChild(c int32, nodes, leaves int) bool {
	if c >= 0 {
		return int(c) < nodes && c > 0
	}
	return int(^c) < leaves
}

func LoadModelFile(path string) (*Model, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadModel(raw)
}

// Score returns the malware probability for a feature vector.
func (m *Model) Score(x []float32) float64 {
	total := 0.0
	for _, t := range m.Trees {
		if len(t.F) == 0 {
			total += t.V[0]
			continue
		}
		node := int32(0)
		for steps := 0; node >= 0 && steps < 4096; steps++ {
			if float64(x[t.F[node]]) <= t.T[node] {
				node = t.L[node]
			} else {
				node = t.R[node]
			}
		}
		if node < 0 {
			total += t.V[^node]
		}
	}
	return 1 / (1 + math.Exp(-total))
}

// Threshold maps a policy sensitivity to a score cut-off; ok=false means ML is off.
func (m *Model) Threshold(sensitivity string) (float64, bool) {
	key := map[string]string{"cautious": "fpr001", "balanced": "fpr01", "aggressive": "fpr1", "paranoid": "fpr1"}[sensitivity]
	t, ok := m.Thresholds[key]
	if !ok {
		return 0, false
	}
	if sensitivity == "paranoid" {
		t = t * 0.8
	}
	return t, true
}
