package main

import "testing"

// TestLadderSweep (BACKLOG T-019) is the capacity-vs-stealth ladder sweep and a
// CONSUMER of the production analyzeEncode. For each SVG class it drives powers-of-
// two payloads (capped at 4x the SVG size) and, per payload, walks a carrier-config
// ladder (least->most aggressive) to find the lowest rung that ENCODES under the
// stealth budget — recording the full per-encode metric row. INFEASIBLE past the
// current ceiling quantifies the headroom future (substitutive/invasive) tiers must unlock.
//
// Run:  go test -mod=vendor -run TestLadderSweep -v
func TestLadderSweep(t *testing.T) {
	type rung struct {
		name         string
		vp, minExist int
		subdivide    bool
	}
	ladder := []rung{
		{"t0-strict", 3, 3, false},
		{"t1-vp4", 4, 3, false},
		{"t1-min2", 3, 2, false},
		{"t2-subdiv", 3, 3, true},
		{"t2-sub-min2", 3, 2, true},
	}
	const renderPx, subPx = 1024.0, 0.5

	t.Logf("%-18s %6s %5s %-11s %4s %6s %6s %7s %8s %6s %5s",
		"class", "payB", "pay%", "rung", "fit", "comp", "compR", "bloat", "overhead", "grow%", "susp")

	for _, c := range svgClasses() {
		inLen := len(c.svg)
		maxPay := min(4*inLen, 8192)
		for pay := 16; pay <= maxPay; pay *= 2 {
			payload := make([]byte, pay)
			for i := range payload {
				payload[i] = byte((i*131 + 7) % 256)
			}
			payPct := 100 * float64(pay) / float64(inLen)

			found := false
			var best EncodeAnalysis
			rungName := "INFEASIBLE"
			for _, r := range ladder {
				var opt options
				setOptionDefaults(&opt)
				opt.visiblePrecision = r.vp
				opt.minExistingDecimals = r.minExist
				opt.subdivide = r.subdivide
				opt.noEncrypt = true
				opt.smart = false
				enc, stats, err := EncodeSVG(c.svg, payload, nil, opt)
				if err != nil {
					continue // capacity too small at this rung
				}
				a := analyzeEncode(c.svg, enc, payload, stats, renderPx, subPx)
				if a.Plausibility.Pass {
					best, rungName, found = a, r.name, true
					break
				}
			}
			if found {
				t.Logf("%-18s %6d %4.0f%% %-11s %4s %6s %6.2f %7.2f %8.2f %5.1f%% %5d",
					c.name, pay, payPct, rungName, "yes", best.CompressionMode, best.CompressionRatio,
					best.Bloat, best.Overhead, best.SizeGrowthPct, best.Plausibility.NumericSuspicion)
			} else {
				t.Logf("%-18s %6d %4.0f%% %-11s %4s %6s %6s %7s %8s %6s %5s",
					c.name, pay, payPct, rungName, "no", "-", "-", "-", "-", "-", "-")
			}
		}
	}
}
