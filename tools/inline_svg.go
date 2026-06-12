//go:build ignore

// inline_svg.go — produce a clean, LOSSLESS, integrity-checked source-code
// representation of ANY SVG, for inlining as source.
//
// Pipeline:  strip non-rendering cruft (KEEP whitespace) -> sha256(stripped)
//            -> choose compression (none|flate|gzip|brotli|auto) -> base64 @<=80 cols.
// The sha256 is of the PRE-compress / PRE-base64 (stripped) bytes, so a consumer can
// verify integrity after base64-decode + decompress. `auto` tries every method and
// picks the smallest, falling back to `none` when compression doesn't help. Self-
// verifies the round-trip. Dev utility (uses the vendored brotli + stdlib).
//
//   go run tools/inline_svg.go [-c auto|none|flate|gzip|brotli] <input.svg>

package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/andybalholm/brotli"
)

var stripRes = []*regexp.Regexp{
	regexp.MustCompile(`(?s)<!--.*?-->`),
	regexp.MustCompile(`(?s)<\?xml.*?\?>`),
	regexp.MustCompile(`(?is)<!DOCTYPE.*?>`),
	regexp.MustCompile(`(?is)<metadata\b.*?</metadata>`),
	regexp.MustCompile(`(?is)<sodipodi:namedview\b.*?(?:/>|</sodipodi:namedview>)`),
	regexp.MustCompile(`\s+(?:inkscape|sodipodi):[\w-]+\s*=\s*"[^"]*"`),
	regexp.MustCompile(`\s+xmlns:(?:inkscape|sodipodi)\s*=\s*"[^"]*"`),
}

func stripNonRendering(svg []byte) []byte {
	s := string(svg)
	for _, re := range stripRes {
		s = re.ReplaceAllString(s, "")
	}
	return []byte(s)
}

type codec struct {
	name string
	enc  func([]byte) []byte
	dec  func([]byte) ([]byte, error)
}

var codecs = []codec{
	{"none", func(b []byte) []byte { return b }, func(b []byte) ([]byte, error) { return b, nil }},
	{"flate", func(b []byte) []byte {
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.BestCompression)
		w.Write(b)
		w.Close()
		return buf.Bytes()
	}, func(b []byte) ([]byte, error) { return io.ReadAll(flate.NewReader(bytes.NewReader(b))) }},
	{"gzip", func(b []byte) []byte {
		var buf bytes.Buffer
		w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		w.Write(b)
		w.Close()
		return buf.Bytes()
	}, func(b []byte) ([]byte, error) {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	}},
	{"brotli", func(b []byte) []byte {
		var buf bytes.Buffer
		w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
		w.Write(b)
		w.Close()
		return buf.Bytes()
	}, func(b []byte) ([]byte, error) { return io.ReadAll(brotli.NewReader(bytes.NewReader(b))) }},
}

func wrap80(s string) string {
	var b strings.Builder
	for len(s) > 80 {
		b.WriteString(s[:80])
		b.WriteByte('\n')
		s = s[80:]
	}
	b.WriteString(s)
	return b.String()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func main() {
	want := flag.String("c", "auto", "compression: auto|none|flate|gzip|brotli")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: go run tools/inline_svg.go [-c method] <input.svg>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fatal(err)
	}

	stripped := stripNonRendering(raw)
	sum := sha256.Sum256(stripped)
	hexsum := hex.EncodeToString(sum[:])

	// compress with every codec; the chosen one is the forced method, or (auto)
	// whichever is smallest — so compression is skipped when it doesn't help.
	fmt.Printf("// %s — stripped + <method> + base64 (lossless)\n", filepath.Base(flag.Arg(0)))
	fmt.Printf("// sha256(stripped, pre-compress) = %s\n", hexsum)
	fmt.Printf("// raw=%dB stripped=%dB ; compressed sizes:\n", len(raw), len(stripped))
	sizes := make([]int, len(codecs))
	var chosen codec
	best := -1
	for i, c := range codecs {
		sizes[i] = len(c.enc(stripped))
		if *want == "auto" {
			if best < 0 || sizes[i] < best {
				best, chosen = sizes[i], c
			}
		} else if c.name == *want {
			chosen = c
		}
	}
	if chosen.enc == nil {
		fatal(fmt.Errorf("unknown method %q", *want))
	}
	for i, c := range codecs {
		mark := ""
		if c.name == chosen.name {
			mark = "  <- chosen"
		}
		fmt.Printf("//   %-7s %5dB%s\n", c.name, sizes[i], mark)
	}

	compressed := chosen.enc(stripped)
	b64 := base64.StdEncoding.EncodeToString(compressed)
	wrapped := wrap80(b64)
	fmt.Printf("// method=%s  compressed=%dB  base64=%dB (%d lines <=80col)\n",
		chosen.name, len(compressed), len(b64), strings.Count(wrapped, "\n")+1)
	fmt.Printf("const svgInline_%s_B64 = `\n%s\n`\n", chosen.name, wrapped)

	// self-verify: base64 -> decompress -> bytes == stripped AND sha256 matches
	cback, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(wrapped, "\n", ""))
	if err != nil {
		fatal(err)
	}
	dec, err := chosen.dec(cback)
	if err != nil {
		fatal(err)
	}
	back := sha256.Sum256(dec)
	if bytes.Equal(dec, stripped) && hex.EncodeToString(back[:]) == hexsum {
		fmt.Printf("// round-trip: PASS (base64 -> %s -> bytes == stripped; sha256 matches)\n", chosen.name)
	} else {
		fmt.Println("// round-trip: FAIL")
		os.Exit(1)
	}
}
