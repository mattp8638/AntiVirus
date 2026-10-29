package fleet

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PII discovery (command pii.scan). Finds files holding personal data so the cloud can rank
// vulnerabilities on those devices higher (cloud: datadiscovery.py). Only counts, types and file paths
// leave the device: never the matched values. The Windows equivalent is the built-in PowerShell script
// "PII discovery" with the same detectors.

type PIIOptions struct {
	Paths          []string `json:"paths"`
	MaxFiles       int      `json:"maxFiles"`
	MaxFileBytes   int64    `json:"maxFileBytes"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

type PIIFile struct {
	Path  string         `json:"path"`
	Types map[string]int `json:"types"`
}

type PIIResult struct {
	FilesScanned int            `json:"filesScanned"`
	FilesWithPII int            `json:"filesWithPii"`
	Counts       map[string]int `json:"counts"`
	Files        []PIIFile      `json:"files"`
	Truncated    bool           `json:"truncated"`
	Roots        []string       `json:"roots"`
}

var (
	piiExtensions = map[string]bool{".txt": true, ".csv": true, ".tsv": true, ".log": true, ".json": true, ".xml": true, ".md": true,
		".docx": true, ".xlsx": true}
	reCard  = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)
	reNINO  = regexp.MustCompile(`(?i)\b([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z])\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b`)
	reTag   = regexp.MustCompile(`<[^>]+>`)
	reBreak = regexp.MustCompile(`</(w:p|w:tc|c|si|row)>`)
	reNHS   = regexp.MustCompile(`\b\d{3}[ -]\d{3}[ -]\d{4}\b`)
	reIBAN  = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	reEmail = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)
	// HMRC never issues these prefixes.
	ninoBadPrefix = map[string]bool{"BG": true, "GB": true, "NK": true, "KN": true, "TN": true, "NT": true, "ZZ": true}
	// Sensitive types make a device "pii-high"; email addresses alone are low sensitivity.
	SensitivePII = map[string]bool{"payment-card": true, "uk-nino": true, "nhs-number": true, "iban": true}
)

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(number string) bool {
	sum, double := 0, false
	for i := len(number) - 1; i >= 0; i-- {
		d := int(number[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func cardIssuer(number string) bool {
	switch {
	case len(number) < 13 || len(number) > 19:
		return false
	case number[0] == '4': // Visa
		return true
	case number[:2] >= "51" && number[:2] <= "55", number[:4] >= "2221" && number[:4] <= "2720": // Mastercard
		return true
	case number[:2] == "34" || number[:2] == "37": // American Express
		return len(number) == 15
	case strings.HasPrefix(number, "6011") || strings.HasPrefix(number, "65"): // Discover
		return true
	}
	return false
}

func nhsValid(number string) bool {
	if len(number) != 10 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(number[i]-'0') * (10 - i)
	}
	check := 11 - sum%11
	if check == 11 {
		check = 0
	}
	return check != 10 && check == int(number[9]-'0')
}

func ibanValid(raw string) bool {
	iban := strings.ReplaceAll(raw, " ", "")
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	remainder := 0
	for _, r := range rearranged {
		var value int
		switch {
		case r >= '0' && r <= '9':
			value = int(r - '0')
			remainder = (remainder*10 + value) % 97
			continue
		case r >= 'A' && r <= 'Z':
			value = int(r-'A') + 10
		default:
			return false
		}
		remainder = (remainder*100 + value) % 97
	}
	return remainder == 1
}

// DetectPII counts validated personal-data matches in text.
func DetectPII(text string) map[string]int {
	found := map[string]int{}
	for _, m := range reCard.FindAllString(text, -1) {
		if n := digitsOnly(m); cardIssuer(n) && luhn(n) {
			found["payment-card"]++
		}
	}
	for _, m := range reNINO.FindAllStringSubmatch(text, -1) {
		if !ninoBadPrefix[strings.ToUpper(m[1])] {
			found["uk-nino"]++
		}
	}
	lower := strings.ToLower(text)
	for _, loc := range reNHS.FindAllStringIndex(text, -1) {
		start := loc[0] - 25
		if start < 0 {
			start = 0
		}
		// The checksum alone matches ~1 in 11 random numbers; also require the word "NHS" nearby.
		if nhsValid(digitsOnly(text[loc[0]:loc[1]])) && strings.Contains(lower[start:loc[0]], "nhs") {
			found["nhs-number"]++
		}
	}
	for _, m := range reIBAN.FindAllString(text, -1) {
		if ibanValid(m) {
			found["iban"]++
		}
	}
	if n := len(reEmail.FindAllString(text, -1)); n > 0 {
		found["email"] += n
	}
	return found
}

// officeText pulls the text parts out of .docx and .xlsx (both are zip archives of XML).
func officeText(path string, limit int64) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	var out bytes.Buffer
	for _, f := range r.File {
		if f.Name != "word/document.xml" && f.Name != "xl/sharedStrings.xml" && !strings.HasPrefix(f.Name, "xl/worksheets/sheet") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		_, _ = io.Copy(&out, io.LimitReader(rc, limit-int64(out.Len())))
		rc.Close()
		out.WriteByte(' ')
		if int64(out.Len()) >= limit {
			break
		}
	}
	// Word splits text into runs: join runs directly, and only paragraphs and cells with a space.
	return reTag.ReplaceAllString(reBreak.ReplaceAllString(out.String(), " "), ""), nil
}

func defaultPIIRoots() []string {
	homes := "/home/*"
	if IsMacOS {
		homes = "/Users/*"
	}
	var roots []string
	for _, pattern := range []string{homes + "/Documents", homes + "/Desktop", homes + "/Downloads", "/root/Documents"} {
		matches, _ := filepath.Glob(pattern)
		roots = append(roots, matches...)
	}
	return roots
}

// ScanPII walks the roots (default: users' Documents, Desktop and Downloads) within the budgets.
func ScanPII(ctx context.Context, opts PIIOptions) (PIIResult, error) {
	if opts.MaxFiles <= 0 || opts.MaxFiles > 100000 {
		opts.MaxFiles = 20000
	}
	if opts.MaxFileBytes <= 0 || opts.MaxFileBytes > 50<<20 {
		opts.MaxFileBytes = 20 << 20
	}
	if opts.TimeoutSeconds <= 0 || opts.TimeoutSeconds > 3600 {
		opts.TimeoutSeconds = 600
	}
	roots := opts.Paths
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			return PIIResult{}, errors.New("scan paths must be absolute")
		}
	}
	if len(roots) == 0 {
		roots = defaultPIIRoots()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutSeconds)*time.Second)
	defer cancel()
	result := PIIResult{Counts: map[string]int{}, Roots: roots}
	stop := errors.New("budget reached")
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil || result.FilesScanned >= opts.MaxFiles {
				result.Truncated = true
				return stop
			}
			if d.IsDir() {
				if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !piiExtensions[ext] || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > opts.MaxFileBytes {
				return nil
			}
			var text string
			if ext == ".docx" || ext == ".xlsx" {
				text, err = officeText(path, opts.MaxFileBytes)
			} else {
				var data []byte
				data, err = os.ReadFile(path)
				text = string(data)
			}
			if err != nil {
				return nil
			}
			result.FilesScanned++
			if types := DetectPII(text); len(types) > 0 {
				result.FilesWithPII++
				for k, v := range types {
					result.Counts[k] += v
				}
				result.Files = append(result.Files, PIIFile{Path: path, Types: types})
			}
			return nil
		})
		if errors.Is(err, stop) {
			break
		}
	}
	// Most sensitive files first; keep the report small.
	sort.SliceStable(result.Files, func(i, j int) bool { return piiWeight(result.Files[i].Types) > piiWeight(result.Files[j].Types) })
	if len(result.Files) > 200 {
		result.Files, result.Truncated = result.Files[:200], true
	}
	return result, nil
}

func piiWeight(types map[string]int) int {
	weight := 0
	for k, v := range types {
		if SensitivePII[k] {
			weight += 1000 * v
		} else {
			weight += v
		}
	}
	return weight
}

// PIIScanContext runs the pii.scan command.
func PIIScanContext(ctx context.Context, raw string) (map[string]interface{}, error) {
	var opts PIIOptions
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &opts); err != nil {
			return nil, err
		}
	}
	result, err := ScanPII(ctx, opts)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(result)
	var out map[string]interface{}
	_ = json.Unmarshal(data, &out)
	return map[string]interface{}{"pii": out}, nil
}
