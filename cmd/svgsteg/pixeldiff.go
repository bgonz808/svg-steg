package main

// diffPixels is the single, pure source of truth for the pixel-diff math. It compares two
// RGBA pixel buffers (each w*h*4 bytes, R,G,B,A order) and returns the changed-pixel count,
// the max per-channel delta, and the mean per-channel delta.
//
// It has no image/oksvg dependency, so it links into EVERY build — native, `-tags norender`,
// and GOOS=js — and both rasterizer sources feed it the same way: oksvg's `image.RGBA.Pix`
// natively, the browser's `getImageData()` buffer in the wasm. That shared math is what makes
// native↔wasm parity (T-039) and the renderer-parity baseline (T-044) provable: identical
// input buffers MUST yield identical stats, so any divergence is the rasterizer, never the math.
//
// Pairs with abs8/max4 (svgsteg.go). The amplified visualization is render-only (diffImages),
// so amplify is not a parameter here.
func diffPixels(a, b []byte, w, h int) (changed int, maxDelta uint8, meanDelta float64) {
	px := w * h
	if w <= 0 || h <= 0 || len(a) < px*4 || len(b) < px*4 {
		return 0, 0, 0
	}
	var sum uint64
	for i := 0; i < px; i++ {
		o := i * 4
		dr := abs8(a[o], b[o])
		dg := abs8(a[o+1], b[o+1])
		db := abs8(a[o+2], b[o+2])
		da := abs8(a[o+3], b[o+3])
		m := max4(dr, dg, db, da)
		if m != 0 {
			changed++
		}
		if m > maxDelta {
			maxDelta = m
		}
		sum += uint64(dr) + uint64(dg) + uint64(db) + uint64(da)
	}
	meanDelta = float64(sum) / float64(px*4)
	return changed, maxDelta, meanDelta
}
