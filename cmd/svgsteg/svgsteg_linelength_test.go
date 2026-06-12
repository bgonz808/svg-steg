package main

import (
	"strings"
	"testing"
)

// TestLineLengthAnomaly reproduces the "blob line" failure mode: an ~11KB line
// spliced into a file whose other lines are short. The detector must flag it both
// as a blob line and as exceeding the source-derived line-length budget.
func TestLineLengthAnomaly(t *testing.T) {
	// normal pretty-printed SVG: uniform short lines (~25 chars)
	normal := "<svg>\n" + strings.Repeat("  <path d=\"M0 0 L10 10\"/>\n", 50) + "</svg>"
	ns := analyzeLineLengths(normal)
	if ns.BlobLines != 0 {
		t.Errorf("normal SVG: BlobLines=%d, want 0", ns.BlobLines)
	}
	if ns.MaxOverP90 > 3 {
		t.Errorf("normal SVG: Max/P90=%.1f, want low/uniform", ns.MaxOverP90)
	}

	// the failure mode: a single ~11KB line among the short ones
	blobLine := `  <path d="` + strings.Repeat("M0 0L1 1", 1400) + `"/>`
	blob := normal + "\n" + blobLine + "\n"
	bs := analyzeLineLengths(blob)
	if bs.BlobLines == 0 {
		t.Errorf("11KB-line SVG: BlobLines=0, want >=1 (blob not detected)")
	}
	if budget := lineLengthBudget(ns.P90); bs.Max <= budget {
		t.Errorf("11KB line (max=%d) should exceed source budget (%d)", bs.Max, budget)
	}
	t.Logf("normal: max=%d p90=%d maxOverP90=%.1f | blob: max=%d blobLines=%d budget=%d",
		ns.Max, ns.P90, ns.MaxOverP90, bs.Max, bs.BlobLines, lineLengthBudget(ns.P90))
}

// TestSourcePlausibility (BACKLOG T-018) exercises the composite post-processing
// stealth gate: a clean additive encode passes the HARD gates (but warns on rising
// precision); an output with a blob line FAILS.
func TestSourcePlausibility(t *testing.T) {
	// (1) clean additive encode -> passes hard gates, warns on the precision tell
	input := string(testCarrierSVG(400))
	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false
	enc, _, err := EncodeSVG([]byte(input), []byte("layered stealth check payload"), nil, opt)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	r := analyzeSourcePlausibility(input, string(enc), 1024, 0.5)
	if !r.Pass {
		t.Errorf("clean additive encode should pass the hard gates; warnings=%v", r.Warnings)
	}
	if r.NumericSuspicionDelta <= 0 {
		t.Errorf("expected precision suspicion to rise (additive tell), delta=%d", r.NumericSuspicionDelta)
	}
	t.Logf("clean encode: numSusp=%d delta=%d wastedAvg=%.2f pass=%v warnings=%v",
		r.NumericSuspicion, r.NumericSuspicionDelta, r.CanvasWastedAvg, r.Pass, r.Warnings)

	// (2) a blob line in the output must FAIL the hard gate
	pretty := "<svg>\n" + strings.Repeat("  <path d=\"M0 0 L10 10\"/>\n", 30) + "</svg>"
	blobbed := pretty + "\n  <path d=\"" + strings.Repeat("M0 0L1 1", 1400) + "\"/>\n"
	rb := analyzeSourcePlausibility(pretty, blobbed, 1024, 0.5)
	if rb.Pass {
		t.Errorf("blob-line output should FAIL the stealth gate; warnings=%v", rb.Warnings)
	}
}
