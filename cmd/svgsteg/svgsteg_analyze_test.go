package main

import "testing"

// TestAnalyzeEncode (BACKLOG T-019) verifies the production composite that the
// sweep / CLI / inspect all consume: sizes, compression, bloat/overhead, and the
// stealth plausibility are populated, and overhead == bloat-1 holds.
func TestAnalyzeEncode(t *testing.T) {
	input := testCarrierSVG(800)
	payload := []byte("analyzeEncode composite test payload — single source of truth")

	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false
	enc, stats, err := EncodeSVG(input, payload, nil, opt)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	a := analyzeEncode(input, enc, payload, stats, 1024, 0.5)

	if a.InputBytes == 0 || a.OutputBytes == 0 || a.PayloadBytes != len(payload) {
		t.Fatalf("sizes not populated: in=%d out=%d pay=%d", a.InputBytes, a.OutputBytes, a.PayloadBytes)
	}
	if a.Bloat <= 0 {
		t.Errorf("additive encode should have positive bloat, got %.3f", a.Bloat)
	}
	if d := a.Overhead - (a.Bloat - 1); d > 1e-9 || d < -1e-9 {
		t.Errorf("overhead (%.6f) must equal bloat-1 (%.6f)", a.Overhead, a.Bloat-1)
	}
	if !a.Plausibility.Pass {
		t.Errorf("clean additive encode should pass plausibility; warnings=%v", a.Plausibility.Warnings)
	}
	if a.CarrierExpansion <= 0 {
		t.Errorf("carrier expansion should be > 0 (raw bits embedded), got %.3f", a.CarrierExpansion)
	}
	t.Logf("comp=%s compR=%.2f | payload-view: bloat=%.2f overhead=%.2f | raw-view: stream=%dB carrierExp=%.2f | grow%%=%.2f precSusp=%d",
		a.CompressionMode, a.CompressionRatio, a.Bloat, a.Overhead,
		a.StreamBytes, a.CarrierExpansion, a.SizeGrowthPct, a.Plausibility.NumericSuspicion)
}
