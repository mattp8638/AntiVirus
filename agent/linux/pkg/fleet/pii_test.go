package fleet

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectPIIValidatesNumbers(t *testing.T) {
	text := `Card 4111 1111 1111 1111 and bad card 4111 1111 1111 1112.
NI number AB 12 34 56 C, invalid prefix GB123456A, invalid letter QQ123456C. NHS number: 943 476 5919. Random 943 476 5919 without the keyword.
IBAN GB82 WEST 1234 5698 7654 32 and broken GB82 WEST 1234 5698 7654 33. Contact jo@example.co.uk`
	got := DetectPII(text)
	want := map[string]int{"payment-card": 1, "uk-nino": 1, "nhs-number": 1, "iban": 1, "email": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %d want %d (%v)", k, got[k], v, got)
		}
	}
}

func TestScanPIIReportsPathsAndCountsOnly(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "customers.csv"), []byte("name,card\nJo,5555555555554444\n"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "notes.txt"), []byte("nothing personal here"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "image.png"), []byte("5555555555554444"), 0o600)
	_ = os.MkdirAll(filepath.Join(root, ".cache"), 0o700)
	_ = os.WriteFile(filepath.Join(root, ".cache", "x.txt"), []byte("5555555555554444"), 0o600)
	docx, _ := os.Create(filepath.Join(root, "payroll.docx"))
	zw := zip.NewWriter(docx)
	w, _ := zw.Create("word/document.xml")
	_, _ = w.Write([]byte(`<w:p><w:r><w:t>NI: AB 12 34 </w:t></w:r><w:r><w:t>56 C</w:t></w:r></w:p>`))
	_ = zw.Close()
	docx.Close()

	result, err := ScanPII(context.Background(), PIIOptions{Paths: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 3 || result.FilesWithPII != 2 || result.Counts["payment-card"] != 1 || result.Counts["uk-nino"] != 1 {
		t.Fatalf("result: %+v", result)
	}
	for _, f := range result.Files {
		if strings.Contains(f.Path, ".cache") {
			t.Fatal("hidden folders are skipped")
		}
	}
	if _, err := ScanPII(context.Background(), PIIOptions{Paths: []string{"relative"}}); err == nil {
		t.Fatal("relative paths are refused")
	}
}
