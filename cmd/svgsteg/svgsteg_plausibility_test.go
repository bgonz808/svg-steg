package main

import "testing"

// TestMeaningfulDecimals checks the research-derived precision-floor formula
// (T-012 research finding 2): meaningful decimals = floor(log10(scale/τ)).
func TestMeaningfulDecimals(t *testing.T) {
	// viewBox 512 wide @ 1024px, τ=0.2 → scale 2 → log10(2/0.2)=1 → 1 meaningful decimal.
	if got := meaningfulDecimals(512, 1024, 0.2); got != 1 {
		t.Errorf("meaningfulDecimals(512,1024,0.2) = %d, want 1", got)
	}
	// small canvas, same resolution → more digits matter.
	if got := meaningfulDecimals(10, 1024, 0.2); got < 2 {
		t.Errorf("small canvas should yield >=2 meaningful decimals, got %d", got)
	}
	// degenerate inputs → 0, never panic.
	for _, ext := range []float64{0, -5} {
		if got := meaningfulDecimals(ext, 1024, 0.2); got != 0 {
			t.Errorf("meaningfulDecimals(%v,...) = %d, want 0", ext, got)
		}
	}
}

// TestCanvasPrecisionFlagsOverfloor: 3-decimal coords on a 512-unit viewBox @1024px
// carry visually-dead precision (meaningful≈1) — flagged as over-floor, which is the
// free-bit budget the perceptual-substitutive model would reclaim.
func TestCanvasPrecisionFlagsOverfloor(t *testing.T) {
	svg := string(testCarrierSVG(200)) // %.3f coords, viewBox 0 0 512 512
	st := analyzeCanvasPrecision(svg, 1024, 0.2)
	t.Logf("meaningful=%d overFloorFrac=%.2f wastedDigits=%d (free budget)",
		st.MeaningfulDecimals, st.OverFloorFrac, st.WastedDigits)
	if st.MeaningfulDecimals >= 3 {
		t.Errorf("expected meaningful < 3 for this canvas, got %d", st.MeaningfulDecimals)
	}
	if st.OverFloorFrac == 0 || st.WastedDigits == 0 {
		t.Errorf("expected visually-dead precision to be detected (free budget > 0)")
	}
}

func TestDecimalCount(t *testing.T) {
	cases := map[string]int{
		"42.137":    3,
		"42":        0,
		"0.000065":  6,
		"-88.21":    2,
		"12345.678": 3,
	}
	for tok, want := range cases {
		if got := decimalCount(tok); got != want {
			t.Errorf("decimalCount(%q) = %d, want %d", tok, got, want)
		}
	}
}

// TestNumericSuspicionNaturalIsLow: a uniform-precision (natural-looking) SVG must
// score low on the eyeball detector.
func TestNumericSuspicionNaturalIsLow(t *testing.T) {
	natural := string(testCarrierSVG(400)) // uniform 3-decimal coords
	p := analyzeNumericStyle(natural)
	score := numericSuspicionScore(p)
	t.Logf("natural: count=%d median=%d max=%d highPrec=%.3f score=%d",
		p.Count, p.MedianDecimals, p.MaxDecimals, p.HighPrecisionFrac, score)
	if score > 10 {
		t.Errorf("uniform-precision natural SVG should score low, got %d", score)
	}
}

// TestNumericSuspicionDetectsAddedPrecision: the eyeball detector must score the
// CURRENT additive scheme's output (carriers gain +carrierDigits decimals) HIGHER
// than the natural input — i.e., it quantifies the "too many sig-figs" tell. This
// is the objective function the perceptual-substitutive carrier model (post-research)
// must drive back down.
func TestNumericSuspicionDetectsAddedPrecision(t *testing.T) {
	natural := string(testCarrierSVG(400)) // uniform 3-decimal
	np := analyzeNumericStyle(natural)
	natScore := numericSuspicionScore(np)

	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false
	encoded, _, err := EncodeSVG([]byte(natural), []byte("eyeball-detector demo payload"), nil, opt)
	if err != nil {
		t.Fatalf("EncodeSVG: %v", err)
	}
	ep := analyzeNumericStyle(string(encoded))
	encScore := numericSuspicionScore(ep)

	t.Logf("natural score=%d (max=%d highPrec=%.3f) | encoded score=%d (max=%d highPrec=%.3f)",
		natScore, np.MaxDecimals, np.HighPrecisionFrac, encScore, ep.MaxDecimals, ep.HighPrecisionFrac)

	if encScore <= natScore {
		t.Errorf("detector should flag added precision: natural=%d encoded=%d", natScore, encScore)
	}
	if ep.MaxDecimals <= np.MaxDecimals {
		t.Errorf("encoded output should show inflated precision: natural max=%d encoded max=%d",
			np.MaxDecimals, ep.MaxDecimals)
	}
}
