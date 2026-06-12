//go:build !js && !norender

// Native SVG renderer (oksvg/rasterx) + every bitmap-dependent feature: the `diff`
// command, smart-mode visual-fidelity check, encode sidecars, and the distortion audit.
// Excluded from GOOS=js (the browser rasterizes via <canvas>) and from `-tags norender`
// (a reduced-footprint build that links none of oksvg/image/x-image). The matching
// stubs live in render_stub.go. See BACKLOG T-040.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
)

// rendererBuiltIn reports whether this build links the SVG rasterizer. Runtime
// feature-gating (validateOpt) and reporting branch on it; render_stub.go sets it false.
const rendererBuiltIn = true

// Hardening bounds for the untrusted-SVG parser. oksvg is unmaintained and ingests
// attacker-controlled XML, so we cap input size and bound render time. NOTE: Go cannot
// interrupt the synchronous oksvg call, so renderTimeout bounds how long the caller
// WAITS, not resource use — on a pathological input the render goroutine runs until it
// finishes. On this one-shot CLI, process exit reclaims it; the timeout matters mainly
// if this renderer is ever embedded in a long-running process.
const (
	maxSVGBytes   = 10 << 20 // 10 MiB
	renderTimeout = 30 * time.Second
)

func cmdDiff(args []string) error {
	var opt options
	fs := baseFlagSet("diff", &opt)
	_ = fs.Parse(args)
	if err := validateOpt(opt); err != nil {
		return err
	}
	if opt.diffAPath == "" || opt.diffBPath == "" {
		return errors.New("diff requires --a original.svg and --b encoded.svg")
	}
	if opt.diffOutPath == "" {
		opt.diffOutPath = "diff.png"
	}
	workDir, err := os.MkdirTemp("", "svgsteg-diff-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	asvg, err := os.ReadFile(opt.diffAPath)
	if err != nil {
		return err
	}
	bsvg, err := os.ReadFile(opt.diffBPath)
	if err != nil {
		return err
	}
	w, h := renderDims(string(asvg), string(bsvg), opt.diffMaxCanvas)
	apng := filepath.Join(workDir, "a.png")
	bpng := filepath.Join(workDir, "b.png")
	if err := renderSVG(opt.diffRenderer, opt.diffAPath, apng, w, h); err != nil {
		return err
	}
	if err := renderSVG(opt.diffRenderer, opt.diffBPath, bpng, w, h); err != nil {
		return err
	}
	ai, err := readPNG(apng)
	if err != nil {
		return err
	}
	bi, err := readPNG(bpng)
	if err != nil {
		return err
	}
	if ai.Bounds().Dx() != bi.Bounds().Dx() || ai.Bounds().Dy() != bi.Bounds().Dy() {
		return fmt.Errorf("rendered PNG sizes differ: %dx%d vs %dx%d", ai.Bounds().Dx(), ai.Bounds().Dy(), bi.Bounds().Dx(), bi.Bounds().Dy())
	}
	diff, changed, maxDelta, meanDelta := diffImages(ai, bi, opt.diffAmplify)
	out, err := os.Create(opt.diffOutPath)
	if err != nil {
		return err
	}
	if err := png.Encode(out, diff); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	total := ai.Bounds().Dx() * ai.Bounds().Dy()
	fmt.Printf("rendered size:       %dx%d\n", ai.Bounds().Dx(), ai.Bounds().Dy())
	fmt.Printf("changed pixels:      %d / %d (%.6f%%)\n", changed, total, 100*float64(changed)/float64(total))
	fmt.Printf("max channel delta:   %d\n", maxDelta)
	fmt.Printf("mean channel delta:  %.6f\n", meanDelta)
	fmt.Printf("diff output:         %s\n", opt.diffOutPath)
	ds := DiffStats{Renderer: opt.diffRenderer, Width: ai.Bounds().Dx(), Height: ai.Bounds().Dy(), Changed: changed, Total: total, ChangedPct: 100 * float64(changed) / float64(total), MaxDelta: maxDelta, MeanDelta: meanDelta}
	if err := checkVisualBudget(ds, opt); err != nil {
		return err
	}
	return nil
}

// renderSVG rasterizes an SVG to a PNG using the in-process oksvg/rasterx renderer,
// which is the sole supported backend. The renderer argument is accepted for call-site
// compatibility but ignored: there are no subprocess shell-outs (rsvg-convert/resvg) and
// no alternate backends, so the binary links no os/exec and cannot spawn external
// processes.
func renderSVG(renderer, inPath, outPath string, w, h int) error {
	_ = renderer
	b, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	if len(b) > maxSVGBytes {
		return fmt.Errorf("SVG input %d bytes exceeds maximum %d (DoS bound)", len(b), maxSVGBytes)
	}
	img, err := renderSVGWithTimeout(b, w, h, renderTimeout)
	if err != nil {
		return err
	}
	return writePNG(outPath, img)
}

// renderSVGWithTimeout runs the oksvg renderer in a side goroutine, returning an error if
// it does not finish within timeout. renderSVGBuiltinOKSVG allocates its own image
// buffer, so an abandoned goroutine shares no state with the caller; the buffered channel
// guarantees it never blocks on send.
func renderSVGWithTimeout(svg []byte, w, h int, timeout time.Duration) (image.Image, error) {
	type result struct {
		img image.Image
		err error
	}
	ch := make(chan result, 1)
	go func() {
		img, err := renderSVGBuiltinOKSVG(svg, w, h)
		ch <- result{img, err}
	}()
	select {
	case r := <-ch:
		return r.img, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("SVG render exceeded %s (input may be pathological)", timeout)
	}
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

func renderSVGBuiltinOKSVG(svg []byte, w, h int) (img image.Image, err error) {
	// Contain panics from the unaudited oksvg parser on malformed input: turn a crash
	// into a returned error so hostile SVG cannot take down the process.
	defer func() {
		if r := recover(); r != nil {
			img = nil
			err = fmt.Errorf("oksvg renderer panicked on input: %v", r)
		}
	}()
	icon, err := oksvg.ReadIconStream(bytes.NewReader(svg))
	if err != nil {
		return nil, err
	}
	icon.SetTarget(0, 0, float64(w), float64(h))
	rgba := image.NewRGBA(image.Rect(0, 0, w, h))
	scanner := rasterx.NewScannerGV(w, h, rgba, rgba.Bounds())
	dasher := rasterx.NewDasher(w, h, scanner)
	icon.Draw(dasher, 1.0)
	return rgba, nil
}

func diffSVGBytes(aSVG, bSVG []byte, renderer string, maxCanvas int, amplify int) (DiffStats, error) {
	workDir, err := os.MkdirTemp("", "svgsteg-smart-diff-*")
	if err != nil {
		return DiffStats{}, err
	}
	defer os.RemoveAll(workDir)
	aPath := filepath.Join(workDir, "a.svg")
	bPath := filepath.Join(workDir, "b.svg")
	if err := os.WriteFile(aPath, aSVG, 0644); err != nil {
		return DiffStats{}, err
	}
	if err := os.WriteFile(bPath, bSVG, 0644); err != nil {
		return DiffStats{}, err
	}
	w, h := renderDims(string(aSVG), string(bSVG), maxCanvas)
	apng := filepath.Join(workDir, "a.png")
	bpng := filepath.Join(workDir, "b.png")
	if err := renderSVG(renderer, aPath, apng, w, h); err != nil {
		return DiffStats{}, err
	}
	if err := renderSVG(renderer, bPath, bpng, w, h); err != nil {
		return DiffStats{}, err
	}
	ai, err := readPNG(apng)
	if err != nil {
		return DiffStats{}, err
	}
	bi, err := readPNG(bpng)
	if err != nil {
		return DiffStats{}, err
	}
	if ai.Bounds().Dx() != bi.Bounds().Dx() || ai.Bounds().Dy() != bi.Bounds().Dy() {
		return DiffStats{}, fmt.Errorf("rendered PNG sizes differ: %dx%d vs %dx%d", ai.Bounds().Dx(), ai.Bounds().Dy(), bi.Bounds().Dx(), bi.Bounds().Dy())
	}
	_, changed, maxDelta, meanDelta := diffImages(ai, bi, amplify)
	total := ai.Bounds().Dx() * ai.Bounds().Dy()
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(changed) / float64(total)
	}
	return DiffStats{Renderer: renderer, Width: ai.Bounds().Dx(), Height: ai.Bounds().Dy(), Changed: changed, Total: total, ChangedPct: pct, MaxDelta: maxDelta, MeanDelta: meanDelta}, nil
}

func emitEncodeSidecars(originalSVG, encodedSVG []byte, opt options, logw io.Writer) error {
	if !opt.emitSidecars || opt.outPath == "" || opt.outPath == "-" {
		return nil
	}
	renderer := opt.visualRenderer
	if strings.TrimSpace(renderer) == "" {
		renderer = "builtin-oksvg"
	}
	maxCanvas := opt.visualMaxCanvas
	if maxCanvas <= 0 {
		maxCanvas = 1024
	}
	prefix := opt.sidecarPrefix
	if prefix == "" {
		prefix = strings.TrimSuffix(opt.outPath, filepath.Ext(opt.outPath))
		if prefix == "" {
			prefix = opt.outPath
		}
	}
	aOut := prefix + ".a.png"
	bOut := prefix + ".b.png"
	diffOut := prefix + ".diff.png"

	workDir, err := os.MkdirTemp("", "svgsteg-encode-sidecars-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	aSVG := filepath.Join(workDir, "a.svg")
	bSVG := filepath.Join(workDir, "b.svg")
	if err := os.WriteFile(aSVG, originalSVG, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(bSVG, encodedSVG, 0644); err != nil {
		return err
	}
	w, h := renderDims(string(originalSVG), string(encodedSVG), maxCanvas)
	aPNG := filepath.Join(workDir, "a.png")
	bPNG := filepath.Join(workDir, "b.png")
	if err := renderSVG(renderer, aSVG, aPNG, w, h); err != nil {
		return err
	}
	if err := renderSVG(renderer, bSVG, bPNG, w, h); err != nil {
		return err
	}
	ai, err := readPNG(aPNG)
	if err != nil {
		return err
	}
	bi, err := readPNG(bPNG)
	if err != nil {
		return err
	}
	if ai.Bounds().Dx() != bi.Bounds().Dx() || ai.Bounds().Dy() != bi.Bounds().Dy() {
		return fmt.Errorf("sidecar rendered PNG sizes differ: %dx%d vs %dx%d", ai.Bounds().Dx(), ai.Bounds().Dy(), bi.Bounds().Dx(), bi.Bounds().Dy())
	}
	diff, _, _, _ := diffImages(ai, bi, opt.diffAmplify)
	if err := copyFile(aPNG, aOut); err != nil {
		return err
	}
	if err := copyFile(bPNG, bOut); err != nil {
		return err
	}
	if err := writePNG(diffOut, diff); err != nil {
		return err
	}
	fmt.Fprintf(logw, "sidecar original:     %s\n", aOut)
	fmt.Fprintf(logw, "sidecar encoded:      %s\n", bOut)
	fmt.Fprintf(logw, "sidecar diff:         %s\n", diffOut)
	return nil
}

func readPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// diffImages is the native adapter over the pure diffPixels: it converts both images to
// RGBA buffers, delegates the stats to diffPixels (single source of truth — identical to the
// wasm path by construction), and additionally renders the amplified visual-diff image.
func diffImages(a, b image.Image, amplify int) (*image.RGBA, int, uint8, float64) {
	w, h := a.Bounds().Dx(), a.Bounds().Dy()
	aRGBA := imageToRGBA(a)
	bRGBA := imageToRGBA(b)
	changed, maxD, mean := diffPixels(aRGBA, bRGBA, w, h)
	// Amplified diff visualization (render-only); per-pixel deltas recomputed from the buffers.
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		o := i * 4
		dr := abs8(aRGBA[o], bRGBA[o])
		dg := abs8(aRGBA[o+1], bRGBA[o+1])
		db := abs8(aRGBA[o+2], bRGBA[o+2])
		out.SetRGBA(i%w, i/w, color.RGBA{R: satMul(dr, amplify), G: satMul(dg, amplify), B: satMul(db, amplify), A: 255})
	}
	return out, changed, maxD, mean
}

// imageToRGBA returns the image's pixels as a tightly-packed RGBA byte buffer (w*h*4,
// alpha-premultiplied) — the format diffPixels consumes and the browser's getImageData yields.
func imageToRGBA(img image.Image) []byte {
	b := img.Bounds()
	if rgba, ok := img.(*image.RGBA); ok && rgba.Stride == b.Dx()*4 && rgba.Rect.Min == (image.Point{}) {
		return rgba.Pix
	}
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), img, b.Min, draw.Src)
	return dst.Pix
}

// auditDistortion renders input vs output and returns the rasterized visual diff (axis 1:
// DISTORTION). Kept separate from analyzeEncode so the sweep stays render-free and fast;
// this is the native/CLI distortion measure (the WASM build computes the same thing
// in-browser via <canvas>). Together, analyzeEncode (capacity-used + suspicion + size) +
// auditDistortion (distortion) give the full capacity-vs-distortion-vs-suspicion audit.
func auditDistortion(input, output []byte) (changedPct float64, maxDelta uint8, meanDelta float64, ok bool) {
	w, h := renderDims(string(input), string(output), 1024)
	if w <= 0 || h <= 0 {
		return
	}
	ai, e1 := renderSVGBuiltinOKSVG(input, w, h)
	bi, e2 := renderSVGBuiltinOKSVG(output, w, h)
	if e1 != nil || e2 != nil || ai.Bounds() != bi.Bounds() {
		return
	}
	_, changed, mx, mean := diffImages(ai, bi, 1)
	if n := w * h; n > 0 {
		changedPct = 100 * float64(changed) / float64(n)
	}
	return changedPct, mx, mean, true
}
