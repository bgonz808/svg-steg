package main

import "testing"

func defaultPolicy(visiblePrecision int) carrierPolicy {
	var opt options
	setOptionDefaults(&opt)
	opt.visiblePrecision = visiblePrecision
	return policyFrom(opt, "")
}

// TestEncodeDecodeNumberRoundtrip (BACKLOG T-008): the string-based carrier must
// round-trip every byte 0..255 across visible precisions and coordinate
// magnitudes (integer parts well within float64's exact range). This is the
// packing core, independent of the SVG plumbing.
func TestEncodeDecodeNumberRoundtrip(t *testing.T) {
	// Bases whose visible part does not round to a whole number at the tested
	// precisions, so the encoded token stays eligible. Whole-rounding cases (visible
	// part -> integer + carrier byte 0) are intentionally NOT round-trippable at the
	// primitive level; the stream encoder skips them (T-011), covered by
	// TestEncodeNearIntegerCoords.
	bases := []string{"0.137", "42.137", "12345.678", "-88.214", "3.14159"}
	for _, vp := range []int{1, 2, 3} {
		pol := defaultPolicy(vp)
		for _, base := range bases {
			for b := 0; b < 256; b++ {
				enc := encodeNumber(base, byte(b), vp)
				got, ok := decodeNumber(enc, pol)
				if !ok {
					t.Fatalf("vp=%d base=%s b=%d: encoded %q not decodable", vp, base, b, enc)
				}
				if got != byte(b) {
					t.Fatalf("vp=%d base=%s b=%d: recovered %d from %q", vp, base, b, got, enc)
				}
			}
		}
	}
}

// TestCarrierEligibility (BACKLOG T-008): the roundedness heuristic — clean
// integers and simple fractions must be SKIPPED (stay clean / non-carriers);
// arbitrary multi-decimal values must be eligible carriers. Pins the heuristic
// so a future change that breaks encoder/decoder agreement is caught.
func TestCarrierEligibility(t *testing.T) {
	pol := defaultPolicy(3)
	cases := []struct {
		tok  string
		want bool
	}{
		{"42.137", true},   // arbitrary decimal
		{"0.881", true},    // sub-1.0 arbitrary decimal
		{"3.14159", true},  // many decimals
		{"-12.347", true},  // negative arbitrary decimal
		{"100", false},     // bare integer
		{"100.000", false}, // integer-like
		{"0.5", false},     // simple fraction 1/2
		{"0.25", false},    // simple fraction 1/4
	}
	for _, c := range cases {
		if got := eligibleCarrier(c.tok, pol); got != c.want {
			t.Errorf("eligibleCarrier(%q) = %v, want %v", c.tok, got, c.want)
		}
	}
}
