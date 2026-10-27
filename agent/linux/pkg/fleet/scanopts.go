package fleet

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ScanOptions are the antimalware policy settings that shape on-demand and scheduled scans.
type ScanOptions struct {
	Archives        bool   // antimalware.scanArchives
	MaxDepth        int    // antimalware.archiveMaxDepth (nesting levels)
	SkipNetwork     bool   // !antimalware.scanNetworkDrives
	CPULimitPercent int    // antimalware.scanCpuLimitPercent (of one core); 0 or 100 = unlimited
	PUA             string // antimalware.puaProtection: off | audit | block
}

// ScanOptionsFromPolicy reads the antimalware module.
func ScanOptionsFromPolicy(p Policy) ScanOptions {
	pua := p.ModuleString("antimalware", "puaProtection", "block")
	if pua != "off" && pua != "audit" {
		pua = "block"
	}
	return ScanOptions{
		Archives:        p.ModuleBool("antimalware", "scanArchives", true),
		MaxDepth:        clampInt(p.ModuleInt("antimalware", "archiveMaxDepth", 5), 1, 20),
		SkipNetwork:     !p.ModuleBool("antimalware", "scanNetworkDrives", false),
		CPULimitPercent: clampInt(p.ModuleInt("antimalware", "scanCpuLimitPercent", 100), 5, 100),
		PUA:             pua,
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------------
// CPU limit: after each file, rest long enough that work stays near the limit of one core.
// ---------------------------------------------------------------------------

type cpuThrottle struct {
	percent int
	debt    time.Duration
	sleep   func(time.Duration)
}

func newCPUThrottle(percent int) *cpuThrottle {
	return &cpuThrottle{percent: percent, sleep: time.Sleep}
}

// after records `work` spent on one file and sleeps in batches of at least 20 ms.
func (t *cpuThrottle) after(work time.Duration) {
	if t == nil || t.percent <= 0 || t.percent >= 100 {
		return
	}
	t.debt += work * time.Duration(100-t.percent) / time.Duration(t.percent)
	if t.debt >= 20*time.Millisecond {
		pause := t.debt
		if pause > 2*time.Second {
			pause = 2 * time.Second
		}
		t.debt = 0
		t.sleep(pause)
	}
}

// ---------------------------------------------------------------------------
// Network file systems
// ---------------------------------------------------------------------------

var networkFSTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "afpfs": true, "webdav": true, "fuse.sshfs": true,
	"sshfs": true, "afs": true, "ceph": true, "glusterfs": true, "fuse.glusterfs": true, "9p": true, "davfs": true, "fuse.rclone": true,
}

// ParseMountInfo returns the network mount points in /proc/self/mountinfo content.
func ParseMountInfo(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		lf, rf := strings.Fields(left), strings.Fields(right)
		if len(lf) < 5 || len(rf) < 1 || !networkFSTypes[rf[0]] {
			continue
		}
		out = append(out, unescapeMount(lf[4]))
	}
	return out
}

var octalEscape = regexp.MustCompile(`\\[0-7]{3}`)

func unescapeMount(s string) string {
	return octalEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, _ := strconv.ParseUint(m[1:], 8, 8)
		return string([]byte{byte(v)})
	})
}

var macMountLine = regexp.MustCompile(`^.+ on (.+) \(([a-z0-9_.]+)[,)]`)

// ParseMacMounts returns the network mount points in `mount` output on macOS.
func ParseMacMounts(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		if m := macMountLine.FindStringSubmatch(line); m != nil && networkFSTypes[m[2]] {
			out = append(out, m[1])
		}
	}
	return out
}

func networkMounts() []string {
	if IsMacOS {
		out, err := exec.Command("mount").Output()
		if err != nil {
			return nil
		}
		return ParseMacMounts(string(out))
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return ParseMountInfo(string(data))
}

// ---------------------------------------------------------------------------
// Archives: zip (and zip-based formats such as .jar/.apk/.docx), tar, gzip and tar.gz, nested up to a depth.
// Limits keep a hostile archive (zip bomb, millions of entries) from stalling the scan.
// ---------------------------------------------------------------------------

const (
	maxArchiveMembers     = 10000
	maxArchiveTotalBytes  = 1 << 30 // uncompressed bytes read per top-level archive
	maxArchiveMemberBytes = 128 << 20
)

type archiveHit struct {
	member string
	family string
	pua    bool
}

type archiveBudget struct {
	members int
	bytes   int64
}

var errArchiveBudget = errors.New("archive limits reached")

func archiveKind(head []byte) string {
	switch {
	case len(head) >= 4 && bytes.Equal(head[:4], []byte("PK\x03\x04")):
		return "zip"
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		return "gzip"
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

// scanArchive looks inside path when it is an archive and returns the first malicious member.
func (s *Scanner) scanArchive(path string, maxDepth int) *archiveHit {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	kind := archiveKind(head[:n])
	if kind == "" || maxDepth < 1 {
		return nil
	}
	budget := &archiveBudget{}
	if kind == "zip" {
		info, err := f.Stat()
		if err != nil {
			return nil
		}
		zr, err := zip.NewReader(f, info.Size())
		if err != nil {
			return nil
		}
		return s.scanZip(zr, "", maxDepth, budget)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	return s.scanStream(bufio.NewReader(f), kind, "", maxDepth, budget)
}

func (s *Scanner) scanZip(zr *zip.Reader, prefix string, depth int, budget *archiveBudget) *archiveHit {
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			continue
		}
		hit, err := s.scanMember(rc, prefix+entry.Name, depth, budget)
		rc.Close()
		if hit != nil || errors.Is(err, errArchiveBudget) {
			return hit
		}
	}
	return nil
}

// scanStream handles tar and gzip (including tar.gz) read sequentially.
func (s *Scanner) scanStream(r *bufio.Reader, kind, prefix string, depth int, budget *archiveBudget) *archiveHit {
	if kind == "gzip" {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil
		}
		defer gz.Close()
		gz.Multistream(false)
		inner := bufio.NewReaderSize(gz, 64<<10)
		head, _ := inner.Peek(512)
		if archiveKind(head) == "tar" {
			return s.scanStream(inner, "tar", prefix, depth, budget) // tar.gz is one level, not two
		}
		hit, _ := s.scanMember(inner, prefix+"(gzip)", depth, budget)
		return hit
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil
		}
		if hdr.Typeflag != tar.TypeReg { // the reader reports old-style regular files as TypeReg too
			continue
		}
		hit, err := s.scanMember(tr, prefix+hdr.Name, depth, budget)
		if hit != nil || errors.Is(err, errArchiveBudget) {
			return hit
		}
	}
}

// scanMember hashes one member (bounded) and descends into it when it is itself an archive.
func (s *Scanner) scanMember(r io.Reader, name string, depth int, budget *archiveBudget) (*archiveHit, error) {
	budget.members++
	if budget.members > maxArchiveMembers || budget.bytes >= maxArchiveTotalBytes {
		return nil, errArchiveBudget
	}
	limit := int64(maxArchiveMemberBytes)
	if remaining := int64(maxArchiveTotalBytes) - budget.bytes; remaining < limit {
		limit = remaining
	}
	// A nested archive (up to 32 MB) is kept in memory so it can be opened without a temp file.
	br := bufio.NewReaderSize(r, 4096)
	head, _ := br.Peek(512)
	var keep bytes.Buffer
	var sink io.Writer = io.Discard
	if depth > 1 && archiveKind(head) != "" {
		sink = &prefixBuffer{buf: &keep, max: 32 << 20}
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(h, sink), io.LimitReader(br, limit+1))
	budget.bytes += n
	if err != nil {
		return nil, nil
	}
	if n > limit {
		return nil, nil // too large to judge by hash; skip it
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if bad, family := s.Verdict(sha); bad {
		return &archiveHit{member: name, family: family, pua: s.IsPUA(sha)}, nil
	}
	if depth <= 1 || keep.Len() != int(n) {
		return nil, nil
	}
	data := keep.Bytes()
	switch archiveKind(data) {
	case "zip":
		if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
			return s.scanZip(zr, name+"!", depth-1, budget), nil
		}
	case "gzip":
		return s.scanStream(bufio.NewReader(bytes.NewReader(data)), "gzip", name+"!", depth-1, budget), nil
	case "tar":
		return s.scanStream(bufio.NewReader(bytes.NewReader(data)), "tar", name+"!", depth-1, budget), nil
	}
	return nil, nil
}

// prefixBuffer stores up to max bytes and silently discards the rest.
type prefixBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *prefixBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) <= room {
			l.buf.Write(p)
		} else {
			l.buf.Write(p[:room])
		}
	}
	return len(p), nil
}
