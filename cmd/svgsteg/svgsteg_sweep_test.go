package main

import "testing"

// TestCapacityStealthSweep (BACKLOG T-014) is the capacity-vs-stealth benchmark
// instrument: across (SVG class × knob) it records carrier capacity and the
// stealth cost of embedding, so we can see the frontier and find upper bounds.
// Run:  go test -mod=vendor -run TestCapacityStealthSweep -v
//
// Axes measured here:
//   - capB    = natural carrier bytes (countEligiblePathNumbers)
//   - inSusp  = axis-3 precision suspicion of the INPUT
//   - outSusp = axis-3 precision suspicion of the ENCODED output
//   - grow%   = output size growth (a partial axis-2 proxy)
//
// KNOWN LIMITS (honest): (1) precision suspicion does NOT yet capture canvas-relative
// implausibility — largecanvas over-precision is under-scored until the precision-floor
// detector (T-013, lossyWAV research) lands. (2) subdivision (Tier 2) is not swept here;
// its cost is structural (vertex density, axis 2) and needs T-015 to measure honestly,
// so including it now would make it look deceptively "free". (3) coords are natural-only.
func TestCapacityStealthSweep(t *testing.T) {
	knobs := []struct {
		name         string
		vp, minExist int
	}{
		{"vp3-min3", 3, 3}, // default
		{"vp4-min3", 4, 3}, // wider visible precision -> wider carriers
		{"vp3-min1", 3, 1}, // relax eligibility -> more carriers, more exposure
	}

	const (
		renderPx = 1024.0
		subPx    = 0.5
	)
	t.Logf("%-18s %-9s %6s %6s %6s %5s %7s %6s",
		"class", "knob", "coords", "capB", "outSus", "mfDec", "wasteAv", "grow%")
	anyCapacity := false

	for _, c := range svgClasses() {
		svg := string(c.svg)
		coords := len(pathNumbers(svg))
		for _, k := range knobs {
			var opt options
			setOptionDefaults(&opt)
			opt.visiblePrecision = k.vp
			opt.minExistingDecimals = k.minExist
			opt.noEncrypt = true
			opt.smart = false

			pol := policyFrom(opt, svg)
			capB := countEligiblePathNumbers(svg, pol)
			if capB > 0 {
				anyCapacity = true
			}
			analyzed := svg // fall back to the input if the test payload doesn't fit
			outSus, grow := -1, 0.0
			payN := min(capB*6/10, 200)
			if payN > 0 {
				payload := make([]byte, payN)
				for i := range payload {
					payload[i] = byte((i*131 + 7) % 256)
				}
				if enc, _, err := EncodeSVG(c.svg, payload, nil, opt); err == nil {
					analyzed = string(enc)
					outSus = numericSuspicionScore(analyzeNumericStyle(analyzed))
					grow = 100 * float64(len(enc)-len(c.svg)) / float64(len(c.svg))
				}
			}
			// axis-3 canvas-relative (T-013): the meaningful-decimal floor + avg
			// over-floor (visually-dead) digits per coord — accounts for canvas SCALE,
			// the blind spot the distribution-only score missed. Axis-2 (XML-syntax)
			// is unchanged by additive embedding (it touches precision, not formatting),
			// so it's not column'd here yet; it activates with subdivision/fallback tiers.
			cp := analyzeCanvasPrecision(analyzed, renderPx, subPx)
			wasteAvg := 0.0
			if cp.Count > 0 {
				wasteAvg = float64(cp.WastedDigits) / float64(cp.Count)
			}

			t.Logf("%-18s %-9s %6d %6d %6d %5d %7.2f %5.1f%%",
				c.name, k.name, coords, capB, outSus, cp.MeaningfulDecimals, wasteAvg, grow)
		}
	}

	if !anyCapacity {
		t.Fatal("sweep found zero carrier capacity across all classes — generator or policy broken")
	}
}
