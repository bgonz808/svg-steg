//go:build !js && !norender

package main

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
)

// linkedinMiniCarrierB64 is the LinkedIn mini mark, inlined (stripped → flate → base64) as the
// proof-of-concept steg carrier so this demo runs without external files. Its integer-only coords
// have no natural carriers, so encoding falls back to an invisible carrier (verified below).
const linkedinMiniCarrierB64 = `
fFPBbtswDP0VQjuLIUVSkos4wHbqJdfcM9eLA6RrkAR20a8fJLtFB6SF4YdHvucnWrLX1/EAr8+nv9fW
Dbfb+WG1mqYJJ8GXy2EViGh1HQ+uWB6u533Xt+586a/9ZewdTMen29C6TORg6I+H4bYU47Gffr28to6A
QHIot9usz/vbAH+Op1PrfhCl9Ds5eGrdVjShGtCjKJr9LBhhRlquWo3CAXO+Y1g6OQxfW8oYZSHd1fbd
lCIDbZkzBpDQYNaOwNCiVzRgQoq+4swHrwFz562GzEpx+k/OHRuhdlRMBu/i5zAbakrVae7Dx3IV7e3Z
C6NGHyii7pUwJpiRgIGBfGYUhf+VohEURbaijA2IEEbdNxgMKlST/6gHr4aN3DVU2AWNaB15DnX/MDbe
DEm8BMwLDRklAHnR8gahQUpeDAODBmQem4SUvx7ikc0wfzMDa4OxbimDImvparHObFBFla6oNAcUE7zn
6ciGMXZM5TAMU4QQkX1I2DBYg7LQJPPHkaQ8HjMmXjiXY0hvbrVZlx9k8y8AAP//
`

// sha256 of the stripped SVG (pre-compress), from inline_svg.go — the integrity anchor.
const linkedinMiniSHA256 = "afeff064df7dec0cca2aab66034e987a3ad8f362b6c5ef6750358e777aadca6f"

// linkedinMiniCarrier decodes the inlined POC carrier (base64 → flate → SVG) and verifies it.
func linkedinMiniCarrier(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(linkedinMiniCarrierB64), ""))
	if err != nil {
		t.Fatalf("carrier base64: %v", err)
	}
	svg, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("carrier flate: %v", err)
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(svg)); sum != linkedinMiniSHA256 {
		t.Fatalf("carrier sha256 mismatch: got %s want %s (bad transcription?)", sum, linkedinMiniSHA256)
	}
	return svg
}

// TestEmbedLinkedInDemo embeds a real LinkedIn URL into the inlined LinkedIn-mini carrier and
// reports the full per-encode analysis. Runs in CI — the carrier is committed (inlined above).
func TestEmbedLinkedInDemo(t *testing.T) {
	svg := linkedinMiniCarrier(t)
	url := []byte("https://www.linkedin.com/in/robertjgonz/")

	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false
	opt.subdivide = true            // minified mini has no natural carriers (precision stripped)
	opt.allowInvisibleCarrier = true // … and subdivision finds none either → fall back to an invisible carrier

	enc, stats, err := EncodeSVG(svg, url, nil, opt)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	a := analyzeEncode(svg, enc, url, stats, 1024, 0.5)

	pol := policyFrom(opt, string(enc))
	rec, _, err := decodeSVGAutoMode(enc, nil, pol, true, true)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(rec, url) {
		t.Fatalf("round-trip mismatch: got %q want %q", rec, url)
	}

	chPct, maxD, meanD, visOK := auditDistortion(svg, enc)

	t.Logf("EMBED %q (%dB) into linkedin.mini.svg (%dB)  ->  recovered: MATCH", url, len(url), len(svg))
	t.Logf("THREE-WAY AUDIT (capacity vs distortion vs suspicion):")
	t.Logf("  CAPACITY  : stream=%dB embedded  carrierExp=%.2f  bloat=%.2f overhead=%.2f  grow=%.2f%%  comp=%s compR=%.2f",
		a.StreamBytes, a.CarrierExpansion, a.Bloat, a.Overhead, a.SizeGrowthPct, a.CompressionMode, a.CompressionRatio)
	if visOK {
		t.Logf("  DISTORTION: changed=%.4f%%  maxΔ=%d  meanΔ=%.4f  (rasterized visual diff)", chPct, maxD, meanD)
	} else {
		t.Logf("  DISTORTION: (render unavailable)")
	}
	t.Logf("  SUSPICION : precision=%d  canvasWastedAv=%.2f  blobLines=%d  styleDrift=%v  pass=%v",
		a.Plausibility.NumericSuspicion, a.Plausibility.CanvasWastedAvg, a.Plausibility.OutputBlobLines,
		a.Plausibility.StyleDrift, a.Plausibility.Pass)
}
