package main

import (
	"bytes"
	"fmt"
	"testing"
)

// testCarrierSVG builds a path-heavy SVG whose coordinates are non-integer,
// non-simple-fraction (eligible carriers), with ample capacity for a small payload.
func testCarrierSVG(points int) []byte {
	var b bytes.Buffer
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M `)
	for i := 0; i < points; i++ {
		if i > 0 {
			b.WriteString(" L ")
		}
		x := 10.137 + float64(i%400) + 0.111
		y := 12.241 + float64((i*7)%400) + 0.222
		fmt.Fprintf(&b, "%.3f %.3f", x, y)
	}
	b.WriteString(`" fill="none" stroke="black"/></svg>`)
	return b.Bytes()
}

// TestVerifyEncodeRoundtrip covers BACKLOG T-010: the post-encode self-check must
// PASS for the correct payload and FAIL loudly on a mismatch.
func TestVerifyEncodeRoundtrip(t *testing.T) {
	svg := testCarrierSVG(600)
	payload := []byte("T-010 round-trip payload")

	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false // deterministic single-path encode

	encoded, _, err := EncodeSVG(svg, payload, nil, opt)
	if err != nil {
		t.Fatalf("EncodeSVG failed: %v", err)
	}

	// Correct payload -> verification must PASS.
	if err := verifyEncodeRoundtrip(encoded, payload, nil, opt, SmartResult{}); err != nil {
		t.Errorf("verify should PASS on the correct payload, got error: %v", err)
	}

	// Mismatched payload -> verification must FAIL (this is the safety guarantee).
	if err := verifyEncodeRoundtrip(encoded, []byte("WRONG payload"), nil, opt, SmartResult{}); err == nil {
		t.Errorf("verify should FAIL on a mismatched payload, but returned nil")
	}
}

// TestEncodeNearIntegerCoords (BACKLOG T-011): an SVG containing coordinates whose
// visible part rounds to a whole number must still round-trip. The encoder must
// skip carriers whose encoded form would read as integer-like (which the decoder
// drops) and use the next eligible token instead.
func TestEncodeNearIntegerCoords(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M `)
	for i := 0; i < 1200; i++ {
		if i > 0 {
			b.WriteString(" L ")
		}
		// half the coords round to whole numbers at vp=3 (.0002 -> .000), half do not.
		fmt.Fprintf(&b, "%.4f %.4f", float64(i%500)+0.0002, float64((i*3)%500)+0.4007)
	}
	b.WriteString(`" fill="none" stroke="black"/></svg>`)
	svg := b.Bytes()

	payload := bytes.Repeat([]byte{0x00}, 24) // zero-heavy: the worst case for the bug
	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false
	opt.compression = "none" // keep literal zero bytes in the stream
	encoded, _, err := EncodeSVG(svg, payload, nil, opt)
	if err != nil {
		t.Fatalf("EncodeSVG with near-integer coords failed: %v", err)
	}
	pol := policyFrom(opt, string(encoded))
	got, _, err := decodeSVGAutoMode(encoded, nil, pol, true, true)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("near-integer round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestEncodeRoundtripExactRecovery is a direct encode->decode round-trip over a
// few payload sizes (BACKLOG T-008 seed): output must decode back to the input.
func TestEncodeRoundtripExactRecovery(t *testing.T) {
	svg := testCarrierSVG(800)
	for _, n := range []int{1, 7, 32, 100} {
		payload := bytes.Repeat([]byte{0xA5}, n)
		var opt options
		setOptionDefaults(&opt)
		opt.noEncrypt = true
		opt.smart = false
		encoded, _, err := EncodeSVG(svg, payload, nil, opt)
		if err != nil {
			t.Fatalf("EncodeSVG(n=%d) failed: %v", n, err)
		}
		pol := policyFrom(opt, string(encoded))
		got, _, err := decodeSVGAutoMode(encoded, nil, pol, true, true)
		if err != nil {
			t.Fatalf("decode(n=%d) failed: %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round-trip mismatch for n=%d: got %d bytes", n, len(got))
		}
	}
}
