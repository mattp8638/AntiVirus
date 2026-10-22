// Package ml implements Fenrir's static PE malware model on the endpoint:
// EMBER v2 feature extraction (a port of ml/fenrir_ml/features.py) and a
// gradient-boosted tree evaluator for the fenrir-gbdt-1 format.
package ml

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
)

const Dim = 2381

var errNotPE = errors.New("not a PE file")

// --------------------------------------------------------------------------- hashing

func murmur3(data []byte) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	var h uint32
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k uint32
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

type item struct {
	token string
	value float64
}

func hashInto(out []float64, offset, n int, items []item) {
	for _, it := range items {
		h := murmur3([]byte(it.token))
		var index int
		if h == math.MinInt32 {
			index = (math.MaxInt32 - (n - 1)) % n
		} else {
			hv := int(h)
			if hv < 0 {
				hv = -hv
			}
			index = hv % n
		}
		if h >= 0 {
			out[offset+index] += it.value
		} else {
			out[offset+index] -= it.value
		}
	}
}

// --------------------------------------------------------------------------- PE parsing

var machines = map[uint16]string{0x0: "UNKNOWN", 0x14c: "I386", 0x162: "R3000", 0x166: "R4000", 0x168: "R10000", 0x169: "WCEMIPSV2",
	0x184: "ALPHA", 0x1a2: "SH3", 0x1a3: "SH3DSP", 0x1a6: "SH4", 0x1a8: "SH5", 0x1c0: "ARM", 0x1c2: "THUMB", 0x1c4: "ARMNT",
	0x1d3: "AM33", 0x1f0: "POWERPC", 0x1f1: "POWERPCFP", 0x200: "IA64", 0x266: "MIPS16", 0x366: "MIPSFPU", 0x466: "MIPSFPU16",
	0x520: "TRICORE", 0xebc: "EBC", 0x8664: "AMD64", 0x9041: "M32R", 0xaa64: "ARM64", 0xc0ee: "CEE"}

type flag struct {
	bit   uint32
	label string
}

var headerChars = []flag{{0x1, "RELOCS_STRIPPED"}, {0x2, "EXECUTABLE_IMAGE"}, {0x4, "LINE_NUMS_STRIPPED"}, {0x8, "LOCAL_SYMS_STRIPPED"},
	{0x10, "AGGRESSIVE_WS_TRIM"}, {0x20, "LARGE_ADDRESS_AWARE"}, {0x80, "BYTES_REVERSED_LO"}, {0x100, "CHARA_32BIT_MACHINE"},
	{0x200, "DEBUG_STRIPPED"}, {0x400, "REMOVABLE_RUN_FROM_SWAP"}, {0x800, "NET_RUN_FROM_SWAP"}, {0x1000, "SYSTEM"}, {0x2000, "DLL"},
	{0x4000, "UP_SYSTEM_ONLY"}, {0x8000, "BYTES_REVERSED_HI"}}

var subsystems = map[uint16]string{0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
	8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER",
	13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}

var dllChars = []flag{{0x20, "HIGH_ENTROPY_VA"}, {0x40, "DYNAMIC_BASE"}, {0x80, "FORCE_INTEGRITY"}, {0x100, "NX_COMPAT"},
	{0x200, "NO_ISOLATION"}, {0x400, "NO_SEH"}, {0x800, "NO_BIND"}, {0x1000, "APPCONTAINER"}, {0x2000, "WDM_DRIVER"},
	{0x4000, "GUARD_CF"}, {0x8000, "TERMINAL_SERVER_AWARE"}}

var sectionChars = []flag{{0x8, "TYPE_NO_PAD"}, {0x20, "CNT_CODE"}, {0x40, "CNT_INITIALIZED_DATA"}, {0x80, "CNT_UNINITIALIZED_DATA"},
	{0x100, "LNK_OTHER"}, {0x200, "LNK_INFO"}, {0x800, "LNK_REMOVE"}, {0x1000, "LNK_COMDAT"}, {0x8000, "GPREL"},
	{0x20000, "MEM_PURGEABLE"}, {0x40000, "MEM_LOCKED"}, {0x80000, "MEM_PRELOAD"}, {0x1000000, "LNK_NRELOC_OVFL"},
	{0x2000000, "MEM_DISCARDABLE"}, {0x4000000, "MEM_NOT_CACHED"}, {0x8000000, "MEM_NOT_PAGED"}, {0x10000000, "MEM_SHARED"},
	{0x20000000, "MEM_EXECUTE"}, {0x40000000, "MEM_READ"}, {0x80000000, "MEM_WRITE"}}

var alignments = map[uint32]string{1: "ALIGN_1BYTES", 2: "ALIGN_2BYTES", 3: "ALIGN_4BYTES", 4: "ALIGN_8BYTES", 5: "ALIGN_16BYTES",
	6: "ALIGN_32BYTES", 7: "ALIGN_64BYTES", 8: "ALIGN_128BYTES", 9: "ALIGN_256BYTES", 10: "ALIGN_512BYTES", 11: "ALIGN_1024BYTES",
	12: "ALIGN_2048BYTES", 13: "ALIGN_4096BYTES", 14: "ALIGN_8192BYTES"}

type section struct {
	name                           string
	rawSize, rawOffset, vsize, rva uint32
	characteristics                uint32
	entropy                        float64
	props                          []string
}

type importLib struct {
	name    string
	entries []string
}

type peFile struct {
	machine, characteristics, magic, subsystem, dllCharacteristics uint16
	timestamp, numberOfSymbols, sizeofCode, sizeofImage            uint32
	sizeofHeaders                                                  uint32
	majorLinker, minorLinker                                       uint8
	majorOS, minorOS, majorImage, minorImage, majorSub, minorSub   uint16
	heapCommit                                                     uint64
	dirs                                                           [][2]uint32
	sections                                                       []section
	imports                                                        []importLib
	exports                                                        []string
}

// reader reads little-endian fields and remembers the first out-of-range access.
type reader struct {
	b   []byte
	err error
}

func (r *reader) u8(o int) uint8 {
	if o < 0 || o+1 > len(r.b) {
		r.err = errNotPE
		return 0
	}
	return r.b[o]
}

func (r *reader) u16(o int) uint16 {
	if o < 0 || o+2 > len(r.b) {
		r.err = errNotPE
		return 0
	}
	return binary.LittleEndian.Uint16(r.b[o:])
}

func (r *reader) u32(o int) uint32 {
	if o < 0 || o+4 > len(r.b) {
		r.err = errNotPE
		return 0
	}
	return binary.LittleEndian.Uint32(r.b[o:])
}

func (r *reader) u64(o int) uint64 {
	if o < 0 || o+8 > len(r.b) {
		r.err = errNotPE
		return 0
	}
	return binary.LittleEndian.Uint64(r.b[o:])
}

// cstr reads a NUL-terminated latin-1 string; ok=false if o is out of range.
func cstr(b []byte, o, limit int) (string, bool) {
	if o < 0 || o >= len(b) {
		return "", false
	}
	end := o + limit
	if end > len(b) {
		end = len(b)
	}
	if i := bytes.IndexByte(b[o:end], 0); i >= 0 {
		end = o + i
	}
	runes := make([]rune, 0, end-o)
	for _, c := range b[o:end] {
		runes = append(runes, rune(c))
	}
	return string(runes), true
}

func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func parsePE(data []byte) (*peFile, error) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return nil, errNotPE
	}
	r := &reader{b: data}
	lfanew := int(r.u32(0x3c))
	if r.err != nil || lfanew+4 > len(data) || !bytes.Equal(data[lfanew:lfanew+4], []byte("PE\x00\x00")) {
		return nil, errNotPE
	}
	pe := &peFile{}
	coff := lfanew + 4
	pe.machine = r.u16(coff)
	nsections := int(r.u16(coff + 2))
	pe.timestamp = r.u32(coff + 4)
	pe.numberOfSymbols = r.u32(coff + 12)
	optSize := int(r.u16(coff + 16))
	pe.characteristics = r.u16(coff + 18)
	opt := coff + 20
	pe.magic = r.u16(opt)
	if r.err != nil || (pe.magic != 0x10b && pe.magic != 0x20b) {
		return nil, errNotPE
	}
	plus := pe.magic == 0x20b
	pe.majorLinker, pe.minorLinker = r.u8(opt+2), r.u8(opt+3)
	pe.sizeofCode = r.u32(opt + 4)
	pe.majorOS, pe.minorOS = r.u16(opt+40), r.u16(opt+42)
	pe.majorImage, pe.minorImage = r.u16(opt+44), r.u16(opt+46)
	pe.majorSub, pe.minorSub = r.u16(opt+48), r.u16(opt+50)
	pe.sizeofImage = r.u32(opt + 56)
	pe.sizeofHeaders = r.u32(opt + 60)
	pe.subsystem = r.u16(opt + 68)
	pe.dllCharacteristics = r.u16(opt + 70)
	var ndirsOff, dirsOff int
	if plus {
		pe.heapCommit = r.u64(opt + 96)
		ndirsOff, dirsOff = opt+108, opt+112
	} else {
		pe.heapCommit = uint64(r.u32(opt + 84))
		ndirsOff, dirsOff = opt+92, opt+96
	}
	if r.err != nil {
		return nil, errNotPE
	}
	ndirs := int(r.u32(ndirsOff))
	if r.err != nil {
		return nil, errNotPE
	}
	if ndirs > 16 {
		ndirs = 16
	}
	for i := 0; i < ndirs; i++ {
		end := dirsOff + 8*i + 8
		if end > opt+optSize || end > len(data) {
			break
		}
		pe.dirs = append(pe.dirs, [2]uint32{r.u32(dirsOff + 8*i), r.u32(dirsOff + 8*i + 4)})
	}

	secOff := opt + optSize
	if nsections > 96 {
		nsections = 96
	}
	for i := 0; i < nsections; i++ {
		o := secOff + 40*i
		if o+40 > len(data) {
			break
		}
		raw := data[o : o+8]
		if j := bytes.IndexByte(raw, 0); j >= 0 {
			raw = raw[:j]
		}
		name, _ := cstr(append(append([]byte{}, raw...), 0), 0, 8)
		s := section{name: name, vsize: r.u32(o + 8), rva: r.u32(o + 12), rawSize: r.u32(o + 16), rawOffset: r.u32(o + 20),
			characteristics: r.u32(o + 36)}
		contentSize := s.rawSize
		if s.vsize != 0 && s.vsize < contentSize {
			contentSize = s.vsize
		}
		start := int64(s.rawOffset)
		if s.rawSize != 0 && start < int64(len(data)) {
			end := start + int64(contentSize)
			if end > int64(len(data)) {
				end = int64(len(data))
			}
			s.entropy = byteEntropy(data[start:end])
		}
		for _, f := range sectionChars {
			if s.characteristics&f.bit != 0 {
				s.props = append(s.props, f.label)
			}
		}
		if a, ok := alignments[(s.characteristics>>20)&0xf]; ok {
			s.props = append(s.props, a)
		}
		pe.sections = append(pe.sections, s)
	}

	rvaToOff := func(rva uint32) (int, bool) {
		for _, s := range pe.sections {
			span := s.vsize
			if s.rawSize > span {
				span = s.rawSize
			}
			if uint64(s.rva) <= uint64(rva) && uint64(rva) < uint64(s.rva)+uint64(span) {
				return int(int64(rva) - int64(s.rva) + int64(s.rawOffset)), true
			}
		}
		if rva < pe.sizeofHeaders {
			return int(rva), true
		}
		return 0, false
	}

	// Imports
	if len(pe.dirs) > 1 && pe.dirs[1][0] != 0 && pe.dirs[1][1] != 0 {
		if o, ok := rvaToOff(pe.dirs[1][0]); ok {
			for n := 0; n < 4096 && o+20 <= len(data); n++ {
				oft := binary.LittleEndian.Uint32(data[o:])
				nameRVA := binary.LittleEndian.Uint32(data[o+12:])
				ft := binary.LittleEndian.Uint32(data[o+16:])
				if oft == 0 && nameRVA == 0 && ft == 0 {
					break
				}
				o += 20
				nameOff, ok := rvaToOff(nameRVA)
				if !ok {
					continue
				}
				dll, ok := cstr(data, nameOff, 256)
				if !ok {
					continue
				}
				lib := importLib{name: dll, entries: []string{}}
				thunk := oft
				if thunk == 0 {
					thunk = ft
				}
				t, ok := rvaToOff(thunk)
				if ok {
					step := 4
					if plus {
						step = 8
					}
					for k := 0; k < 65536 && t >= 0 && t+step <= len(data); k++ {
						var value, ordinalFlag uint64
						if plus {
							value, ordinalFlag = binary.LittleEndian.Uint64(data[t:]), 1<<63
						} else {
							value, ordinalFlag = uint64(binary.LittleEndian.Uint32(data[t:])), 1<<31
						}
						if value == 0 {
							break
						}
						t += step
						if value&ordinalFlag != 0 {
							lib.entries = append(lib.entries, "ordinal"+strconv.FormatUint(value&0xffff, 10))
							continue
						}
						if hint, ok := rvaToOff(uint32(value & 0x7fffffff)); ok {
							if fn, ok := cstr(data, hint+2, 10000); ok {
								lib.entries = append(lib.entries, fn)
							}
						}
					}
				}
				pe.imports = append(pe.imports, lib)
			}
		}
	}

	// Exports (named only)
	if len(pe.dirs) > 0 && pe.dirs[0][0] != 0 && pe.dirs[0][1] != 0 {
		if o, ok := rvaToOff(pe.dirs[0][0]); ok {
			er := &reader{b: data}
			nNames := int(er.u32(o + 24))
			namesRVA := er.u32(o + 32)
			if er.err == nil {
				if namesOff, ok := rvaToOff(namesRVA); ok {
					if nNames > 65536 {
						nNames = 65536
					}
					for i := 0; i < nNames; i++ {
						nr := &reader{b: data}
						rva := nr.u32(namesOff + 4*i)
						if nr.err != nil {
							break
						}
						if off, ok := rvaToOff(rva); ok {
							if name, ok := cstr(data, off, 10000); ok {
								pe.exports = append(pe.exports, name)
							}
						}
					}
				}
			}
		}
	}
	return pe, nil
}

// IsPE reports whether data parses as a PE image.
func IsPE(data []byte) bool {
	_, err := parsePE(data)
	return err == nil
}

// --------------------------------------------------------------------------- feature blocks

func byteHistogram(data []byte, out []float64) {
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	if total == 0 {
		total = 1
	}
	for i, c := range counts {
		out[i] = float64(c) / total
	}
}

func entropyBin(block []byte, window int) (int, [16]int) {
	var c [16]int
	for _, b := range block {
		c[b>>4]++
	}
	h := 0.0
	for _, count := range c {
		if count > 0 {
			p := float64(count) / float64(window)
			h -= p * math.Log2(p)
		}
	}
	bin := int(h * 2 * 2)
	if bin > 15 {
		bin = 15
	}
	return bin, c
}

func byteEntropyHistogram(data []byte, out []float64) {
	const step, window = 1024, 2048
	var acc [256]int
	add := func(block []byte) {
		bin, c := entropyBin(block, window)
		for j := 0; j < 16; j++ {
			acc[bin*16+j] += c[j]
		}
	}
	if len(data) < window {
		add(data)
	} else {
		for start := 0; start+window <= len(data); start += step {
			add(data[start : start+window])
		}
	}
	total := 0
	for _, v := range acc {
		total += v
	}
	t := float64(total)
	if t == 0 {
		t = 1
	}
	for i, v := range acc {
		out[i] = float64(v) / t
	}
}

func countFold(data []byte, pattern string) int {
	n, p := 0, len(pattern)
	for i := 0; i+p <= len(data); {
		if strings.EqualFold(string(data[i:i+p]), pattern) {
			n++
			i += p
		} else {
			i++
		}
	}
	return n
}

func countURLs(data []byte) int {
	n := 0
	for i := 0; i+7 <= len(data); i++ {
		if !strings.EqualFold(string(data[i:i+4]), "http") {
			continue
		}
		j := i + 4
		if j < len(data) && (data[j] == 's' || data[j] == 'S') {
			j++
		}
		if j+3 <= len(data) && string(data[j:j+3]) == "://" {
			n++
			i = j + 2
		}
	}
	return n
}

func stringFeatures(data []byte, out []float64) {
	var dist [96]int
	numStrings, totalLen := 0, 0
	run := 0
	flush := func(end int) {
		if run >= 5 {
			numStrings++
			totalLen += run
			for _, b := range data[end-run : end] {
				dist[b-0x20]++
			}
		}
		run = 0
	}
	for i, b := range data {
		if b >= 0x20 && b <= 0x7f {
			run++
		} else {
			flush(i)
		}
	}
	flush(len(data))
	printables := 0
	for _, c := range dist {
		printables += c
	}
	avg, entropy := 0.0, 0.0
	if numStrings > 0 {
		avg = float64(totalLen) / float64(numStrings)
		for _, c := range dist {
			if c > 0 {
				p := float64(c) / float64(printables)
				entropy -= p * math.Log2(p)
			}
		}
	}
	div := float64(printables)
	if div == 0 {
		div = 1
	}
	out[0], out[1], out[2] = float64(numStrings), avg, float64(printables)
	for i, c := range dist {
		out[3+i] = float64(c) / div
	}
	out[99] = entropy
	out[100] = float64(countFold(data, `c:\`))
	out[101] = float64(countURLs(data))
	out[102] = float64(bytes.Count(data, []byte("HKEY_")))
	out[103] = float64(bytes.Count(data, []byte("MZ")))
}

func dirPresent(pe *peFile, i int) float64 {
	if len(pe.dirs) > i && pe.dirs[i][0] != 0 && pe.dirs[i][1] != 0 {
		return 1
	}
	return 0
}

func labels(value uint32, flags []flag) []item {
	var out []item
	for _, f := range flags {
		if value&f.bit != 0 {
			out = append(out, item{f.label, 1})
		}
	}
	return out
}

func hasProp(s section, p string) bool {
	for _, x := range s.props {
		if x == p {
			return true
		}
	}
	return false
}

// Extract returns the 2381-float EMBER v2 vector (float32, like the training data).
func Extract(data []byte) []float32 {
	v := make([]float64, Dim)
	byteHistogram(data, v[0:256])
	byteEntropyHistogram(data, v[256:512])
	stringFeatures(data, v[512:616])
	pe, err := parsePE(data)
	if err != nil {
		v[616] = float64(len(data))
		return toF32(v)
	}
	imported := 0
	for _, lib := range pe.imports {
		imported += len(lib.entries)
	}
	copy(v[616:626], []float64{float64(len(data)), float64(pe.sizeofImage), dirPresent(pe, 6), float64(len(pe.exports)),
		float64(imported), dirPresent(pe, 5), dirPresent(pe, 2), dirPresent(pe, 4), dirPresent(pe, 9), float64(pe.numberOfSymbols)})

	o := 626
	v[o] = float64(pe.timestamp)
	machine, ok := machines[pe.machine]
	if !ok {
		machine = "UNKNOWN"
	}
	hashInto(v, o+1, 10, []item{{machine, 1}})
	hashInto(v, o+11, 10, labels(uint32(pe.characteristics), headerChars))
	sub, ok := subsystems[pe.subsystem]
	if !ok {
		sub = "UNKNOWN"
	}
	hashInto(v, o+21, 10, []item{{sub, 1}})
	hashInto(v, o+31, 10, labels(uint32(pe.dllCharacteristics), dllChars))
	magic := "PE32"
	if pe.magic == 0x20b {
		magic = "PE32_PLUS"
	}
	hashInto(v, o+41, 10, []item{{magic, 1}})
	copy(v[o+51:o+62], []float64{float64(pe.majorImage), float64(pe.minorImage), float64(pe.majorLinker), float64(pe.minorLinker),
		float64(pe.majorOS), float64(pe.minorOS), float64(pe.majorSub), float64(pe.minorSub), float64(pe.sizeofCode),
		float64(pe.sizeofHeaders), float64(pe.heapCommit)})

	o = 688
	var zero, empty, rx, w float64
	var sizes, ents, vsizes []item
	entry := ""
	foundEntry := false
	for _, s := range pe.sections {
		if s.rawSize == 0 {
			zero++
		}
		if s.name == "" {
			empty++
		}
		if hasProp(s, "MEM_READ") && hasProp(s, "MEM_EXECUTE") {
			rx++
		}
		if hasProp(s, "MEM_WRITE") {
			w++
		}
		if !foundEntry && hasProp(s, "MEM_EXECUTE") {
			entry, foundEntry = s.name, true
		}
		sizes = append(sizes, item{s.name, float64(s.rawSize)})
		ents = append(ents, item{s.name, s.entropy})
		vsizes = append(vsizes, item{s.name, float64(s.vsize)})
	}
	copy(v[o:o+5], []float64{float64(len(pe.sections)), zero, empty, rx, w})
	hashInto(v, o+5, 50, sizes)
	hashInto(v, o+55, 50, ents)
	hashInto(v, o+105, 50, vsizes)
	var entryChars []item
	for _, ch := range entry {
		entryChars = append(entryChars, item{string(ch), 1})
	}
	hashInto(v, o+155, 50, entryChars)
	var entryProps []item
	for _, s := range pe.sections {
		if s.name == entry {
			for _, p := range s.props {
				entryProps = append(entryProps, item{p, 1})
			}
		}
	}
	hashInto(v, o+205, 50, entryProps)

	libSet := map[string]bool{}
	var libs, funcs []item
	for _, lib := range pe.imports {
		lower := strings.ToLower(lib.name)
		libSet[lower] = true
		for _, e := range lib.entries {
			funcs = append(funcs, item{lower + ":" + e, 1})
		}
	}
	names := make([]string, 0, len(libSet))
	for name := range libSet {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		libs = append(libs, item{name, 1})
	}
	hashInto(v, 943, 256, libs)
	hashInto(v, 943+256, 1024, funcs)

	var exports []item
	for _, e := range pe.exports {
		exports = append(exports, item{e, 1})
	}
	hashInto(v, 2223, 128, exports)

	for i, d := range pe.dirs {
		if i >= 15 {
			break
		}
		v[2351+2*i] = float64(d[1])
		v[2351+2*i+1] = float64(d[0])
	}
	return toF32(v)
}

func toF32(v []float64) []float32 {
	out := make([]float32, len(v))
	for i, x := range v {
		out[i] = float32(x)
	}
	return out
}
