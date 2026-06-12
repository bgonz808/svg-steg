//go:build ignore

// renderparity.go — produces the oksvg "source" renders for the renderer-parity baseline
// (BACKLOG T-044). It rasterizes each fixture SVG with the in-process oksvg/rasterx renderer
// at a fixed size on a WHITE background and writes out/parity/<name>.svg + out/parity/img/<name>.<res>.oksvg.png.
// The browser harness (parity.html) then canvas-rasterizes the SAME SVGs and diffs against
// these PNGs (via the wasm diffPixels) to measure how far the two rasterizers diverge — the
// renderer-noise floor that T-043 will compare the steg perturbation against.
//
// White background on both sides isolates rasterization (shape/AA edges) from alpha
// premultiplication differences, so the divergence is about the engines, not the alpha model.
//
//	go run tools/renderparity.go
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
)

// Square (1:1) resolutions, powers of two — the canvas size both rasterizers MUST share at
// each step (a size/aspect mismatch would measure scaling, not the engines). Tests the theory
// that disagreement-% falls as resolution rises (edges ~linear, pixels ~quadratic → ~1/res).
var resolutions = []int{16, 32, 64, 128, 256, 512, 1024}

// Fixtures chosen to stress anti-aliasing / hinting differences between rasterizers:
// diagonals, a Bézier curve, a thin circle, and a filled polygon (AA on fill edges).
var fixtures = map[string]string{
	"diagonal": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256"><path fill="none" stroke="#0a66c2" stroke-width="2" d="M8 8 L248 248 M248 8 L8 248"/></svg>`,
	"curve":    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256"><path fill="none" stroke="#111" stroke-width="3" d="M16 240 C 80 16, 176 16, 240 240"/></svg>`,
	"circle":   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256"><circle cx="128" cy="128" r="100" fill="none" stroke="#c00" stroke-width="2"/></svg>`,
	"fill":     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256"><polygon points="128,24 224,200 32,200" fill="#0a66c2"/></svg>`,
}

const linkedinMini2 = `<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" width="800" height="800" viewBox="0 0 382 382"><path fill="#0077b7" d="M347.445 0H34.555C15.471 0 0 15.471 0 34.555v312.889C0 366.529 15.471 382 34.555 382h312.889C366.529 382 382 366.529 382 347.444V34.555C382 15.471 366.529 0 347.445 0M118.207 329.844c0 5.554-4.502 10.056-10.056 10.056H65.345c-5.554 0-10.056-4.502-10.056-10.056V150.403c0-5.554 4.502-10.056 10.056-10.056h42.806c5.554 0 10.056 4.502 10.056 10.056zM86.748 123.432c-22.459 0-40.666-18.207-40.666-40.666S64.289 42.1 86.748 42.1s40.666 18.207 40.666 40.666-18.206 40.666-40.666 40.666M341.91 330.654a9.247 9.247 0 0 1-9.246 9.246H286.73a9.247 9.247 0 0 1-9.246-9.246v-84.168c0-12.556 3.683-55.021-32.813-55.021-28.309 0-34.051 29.066-35.204 42.11v97.079a9.246 9.246 0 0 1-9.246 9.246h-44.426a9.247 9.247 0 0 1-9.246-9.246V149.593a9.247 9.247 0 0 1 9.246-9.246h44.426a9.247 9.247 0 0 1 9.246 9.246v15.655c10.497-15.753 26.097-27.912 59.312-27.912 73.552 0 73.131 68.716 73.131 106.472z"/></svg>`

func renderOksvg(svg []byte, w, h int) (*image.RGBA, error) {
	icon, err := oksvg.ReadIconStream(bytes.NewReader(svg))
	if err != nil {
		return nil, err
	}
	icon.SetTarget(0, 0, float64(w), float64(h))
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(rgba, rgba.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src) // white bg
	scanner := rasterx.NewScannerGV(w, h, rgba, rgba.Bounds())
	icon.Draw(rasterx.NewDasher(w, h, scanner), 1.0)
	return rgba, nil
}

func main() {
	variant := flag.String("variant", "", `"upstream" renders into img-upstream/ (build with go.upstream.mod); empty = patched`)
	flag.Parse()
	const dir = "web/out/parity"
	imgSuffix := ""
	if *variant == "upstream" {
		imgSuffix = "-upstream"
	}
	imgDir := filepath.Join(dir, "img"+imgSuffix)
	if err := os.MkdirAll(imgDir, 0o755); err != nil {
		panic(err)
	}
	emit := func(name string, svg []byte) {
		if err := os.WriteFile(filepath.Join(dir, name+".svg"), svg, 0o644); err != nil {
			panic(err)
		}
		for _, res := range resolutions {
			img, err := renderOksvg(svg, res, res)
			if err != nil {
				panic(err)
			}
			f, err := os.Create(filepath.Join(imgDir, fmt.Sprintf("%s.%d.oksvg.png", name, res)))
			if err != nil {
				panic(err)
			}
			if err := png.Encode(f, img); err != nil {
				_ = f.Close()
				panic(err)
			}
			_ = f.Close()
		}
		fmt.Printf("wrote %s.svg + oksvg renders at %v\n", name, resolutions)
	}

	order := []string{"diagonal", "curve", "circle", "fill"}
	for _, name := range order {
		emit(name, []byte(fixtures[name]))
	}
	emit("linkedin", []byte(linkedinMini2))
	order = append(order, "linkedin")
	// Manifest so parity.html knows which fixtures were actually produced.
	if err := os.WriteFile(filepath.Join(dir, "fixtures.json"), []byte(`["`+strings.Join(order, `","`)+`"]`), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("done — open parity.html to sweep across resolutions (%d fixtures)\n", len(order))
}
