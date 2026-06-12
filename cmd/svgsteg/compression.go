package main

import (
	"fmt"
	"sort"
	"strings"
)

// compressionStats records which codec was chosen and the compressed size.
type compressionStats struct {
	ID   byte
	Name string
	Size int
}

// Stable on-the-wire codec IDs (stored in the stream — never renumber).
const (
	compNone byte = iota
	compFlateFast
	compFlateDefault
	compFlateBest
	compBrotli
	compZstdFast
	compZstdDefault
)

// codecSpec is one registered compression codec. Codecs register themselves from
// build-tagged files (compression_stdlib.go, compression_brotli.go, …) so the set
// linked in follows the build: brotli drops with `-tags nobrotli`, and all Go codecs
// drop for GOOS=js (the browser supplies compression there). `none` is always present.
type codecSpec struct {
	id     byte
	name   string
	inAuto bool // included in the "auto" sweep (flate-best is explicit-only)
	encode func([]byte) ([]byte, error)
	decode func([]byte) ([]byte, error)
}

var (
	codecRegistry []codecSpec
	codecByName   = map[string]int{} // name -> index into codecRegistry
	codecByID     = map[byte]int{}   // id   -> index into codecRegistry
)

func registerCodec(c codecSpec) {
	codecByName[c.name] = len(codecRegistry)
	codecByID[c.id] = len(codecRegistry)
	codecRegistry = append(codecRegistry, c)
}

func init() {
	// Always available, no external dependency.
	registerCodec(codecSpec{
		id: compNone, name: "none", inAuto: true,
		encode: func(b []byte) ([]byte, error) { out := make([]byte, len(b)); copy(out, b); return out, nil },
		decode: func(b []byte) ([]byte, error) { out := make([]byte, len(b)); copy(out, b); return out, nil },
	})
}

func validCompressionMode(mode string) bool {
	mode = strings.ToLower(mode)
	if mode == "auto" {
		return true
	}
	_, ok := codecByName[mode]
	return ok
}

// chooseCompression compresses in with the named codec, or (mode=="auto") with every
// auto-eligible registered codec and returns the smallest. The auto sweep is ordered by
// stable ID, so the result is deterministic regardless of registration/init order.
func chooseCompression(in []byte, mode string) ([]byte, compressionStats, error) {
	mode = strings.ToLower(mode)
	var cands []int
	switch mode {
	case "auto":
		for i := range codecRegistry {
			if codecRegistry[i].inAuto {
				cands = append(cands, i)
			}
		}
		sort.Slice(cands, func(a, b int) bool { return codecRegistry[cands[a]].id < codecRegistry[cands[b]].id })
	default:
		if i, ok := codecByName[mode]; ok {
			cands = []int{i}
		}
	}
	if len(cands) == 0 {
		return nil, compressionStats{}, fmt.Errorf("unknown compression mode %q", mode)
	}
	var best []byte
	var bestStat compressionStats
	for n, idx := range cands {
		c := codecRegistry[idx]
		out, err := c.encode(in)
		if err != nil {
			return nil, compressionStats{}, fmt.Errorf("%s compression failed: %w", c.name, err)
		}
		if n == 0 || len(out) < len(best) {
			best = out
			bestStat = compressionStats{ID: c.id, Name: c.name, Size: len(out)}
		}
	}
	return best, bestStat, nil
}

func decompressByID(id byte, in []byte) ([]byte, error) {
	if i, ok := codecByID[id]; ok {
		return codecRegistry[i].decode(in)
	}
	return nil, fmt.Errorf("unknown compression id %d", id)
}
