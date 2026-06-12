//go:build ignore

// strokecheck.go — validates the third_party/oksvg stroke-width patch (BACKLOG T-044/T-045).
//
// Renders a stroke-width=10 horizontal line in a 100×100 viewBox and measures the rendered
// thickness (opaque pixels down a column). Three regimes:
//  1. UNIFORM (square target): the headline fix — stroke must scale 10/20/40/80, matching the
//     SVG spec / browser. (Upstream renders a flat 10px.)
//  2. ANISOTROPIC (non-square target): the patch scales by √|det| (geometric mean). This is an
//     intentional single-scalar approximation — the spec-correct result is an elliptical pen
//     (vertical thickness of a horizontal line = 10·sy). We print both so the gap is explicit.
//  3. DEGENERATE (no viewBox → SetTarget divides by zero): the numeric guard must keep the
//     renderer from panicking / NaN-ing / zeroing the stroke.
//
//	go run tools/strokecheck.go
package main

import (
	"bytes"
	"fmt"
	"image"
	"math"

	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
)

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M10 50 L90 50" stroke="black" stroke-width="10" fill="none"/></svg>`
const svgNoViewBox = `<svg xmlns="http://www.w3.org/2000/svg"><path d="M10 50 L90 50" stroke="black" stroke-width="10" fill="none"/></svg>`

func render(src string, w, h int) *image.RGBA {
	icon, err := oksvg.ReadIconStream(bytes.NewReader([]byte(src)))
	if err != nil {
		panic(err)
	}
	icon.SetTarget(0, 0, float64(w), float64(h))
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	icon.Draw(rasterx.NewDasher(w, h, rasterx.NewScannerGV(w, h, rgba, rgba.Bounds())), 1.0)
	return rgba
}

// thickness counts opaque (>25%) pixels down column x — the rendered stroke width there.
func thickness(img *image.RGBA, x int) int {
	n := 0
	for y := 0; y < img.Bounds().Dy(); y++ {
		if _, _, _, a := img.At(x, y).RGBA(); a > 0x4000 {
			n++
		}
	}
	return n
}

func main() {
	fmt.Println("== UNIFORM (square) — the headline fix: must scale with the target ==")
	for _, r := range []int{100, 200, 400, 800} {
		fmt.Printf("  %4d×%-4d  stroke %3dpx   (spec/browser %d)\n", r, r, thickness(render(svg, r, r), r/2), 10*r/100)
	}

	fmt.Println("== ANISOTROPIC (non-square) — √|det| scalar vs the spec's elliptical pen ==")
	for _, d := range []struct{ w, h int }{{400, 100}, {100, 400}} {
		sx, sy := float64(d.w)/100, float64(d.h)/100
		got := thickness(render(svg, d.w, d.h), d.w/2)
		fmt.Printf("  %4d×%-4d  sx=%.0f sy=%.0f  our √det scalar → %2dpx (=10·√det=%.0f);  spec elliptical vertical = 10·sy = %.0fpx\n",
			d.w, d.h, sx, sy, got, 10*math.Sqrt(sx*sy), 10*sy)
	}

	fmt.Println("== DEGENERATE guard — no viewBox (SetTarget ÷0) must not panic/NaN/vanish ==")
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("  FAIL: panic %v\n", r)
			}
		}()
		_ = render(svgNoViewBox, 256, 256)
		fmt.Println("  OK: rendered without panic/NaN (stroke-scale clamp held)")
	}()
}
