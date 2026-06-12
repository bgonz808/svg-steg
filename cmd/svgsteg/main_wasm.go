//go:build js

// Browser/WASM entry. Exposes svgstegEncode() to JS via syscall/js. No CLI, no
// runtime rendering (the page does the visual diff in <canvas>); compression uses the
// wasm codec set (`none` — sufficient for short URL payloads). The async browser
// CompressionStream bridge is a later enhancement, not needed for the URL pet-toy.

package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	js.Global().Set("svgstegEncode", js.FuncOf(svgstegEncode))
	js.Global().Set("svgstegDiffPixels", js.FuncOf(svgstegDiffPixels))
	js.Global().Set("svgstegReady", js.ValueOf(true))
	select {} // keep the instance alive for callbacks
}

// svgstegEncode(carrierSVG, payloadText[, opts]) -> { svg, ...stats } | { error }.
// opts (object, optional): visiblePrecision:int, minExistingDecimals:int,
// subdivide:bool, compression:string. Encrypt is off (this is a public watermark).
func svgstegEncode(_ js.Value, args []js.Value) (out any) {
	defer func() {
		if r := recover(); r != nil {
			out = map[string]any{"error": fmt.Sprintf("encode panic: %v", r)}
		}
	}()

	if len(args) < 2 {
		return map[string]any{"error": "usage: svgstegEncode(carrierSVG, payloadText[, opts])"}
	}
	carrier := []byte(args[0].String())
	payload := []byte(args[1].String())

	// LinkedIn-only scope for the web product — baked into the artifact, not just the UI.
	// (The core EncodeSVG and the CLI stay general-purpose.)
	if !isLinkedInURL(string(payload)) {
		return map[string]any{"error": "only LinkedIn URLs are accepted (https://www.linkedin.com/…)"}
	}

	var opt options
	setOptionDefaults(&opt)
	opt.noEncrypt = true
	opt.smart = false
	if len(args) >= 3 && args[2].Type() == js.TypeObject {
		o := args[2]
		if v := o.Get("visiblePrecision"); v.Type() == js.TypeNumber {
			opt.visiblePrecision = v.Int()
		}
		if v := o.Get("minExistingDecimals"); v.Type() == js.TypeNumber {
			opt.minExistingDecimals = v.Int()
		}
		if v := o.Get("subdivide"); v.Type() == js.TypeBoolean {
			opt.subdivide = v.Bool()
		}
		if v := o.Get("compression"); v.Type() == js.TypeString && v.String() != "" {
			opt.compression = v.String()
		}
	}

	enc, stats, err := EncodeSVG(carrier, payload, nil, opt)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Round-trip self-check: decode the output with the same policy and confirm the payload recovers.
	pol := policyFrom(opt, string(enc))
	if rec, _, derr := decodeSVGAutoMode(enc, nil, pol, true, true); derr != nil || string(rec) != string(payload) {
		msg := "round-trip self-check failed: output did not decode back to the payload"
		if derr != nil {
			msg = "round-trip self-check failed: " + derr.Error()
		}
		return map[string]any{"error": msg}
	}
	return map[string]any{
		"svg":          string(enc),
		"inputBytes":   len(carrier),
		"outputBytes":  len(enc),
		"payloadBytes": len(payload),
		"streamBytes":  stats.StreamBytes,
		"compression":  stats.CompressionMode,
		"verified":     true,
	}
}

// svgstegDiffPixels(aRGBA, bRGBA, w, h) -> { changed, total, changedPct, maxDelta, meanDelta } | { error }.
// aRGBA/bRGBA are Uint8Array RGBA buffers (w*h*4) the page reads from canvas getImageData. The
// rasterization happens in JS (async, on <canvas>); this runs the SAME pure Go pixel-diff math the
// native build uses (diffPixels), so native and in-browser stats are identical given identical
// pixels — the parity substrate for T-044/T-042.
func svgstegDiffPixels(_ js.Value, args []js.Value) (out any) {
	defer func() {
		if r := recover(); r != nil {
			out = map[string]any{"error": fmt.Sprintf("diffPixels panic: %v", r)}
		}
	}()
	if len(args) < 4 {
		return map[string]any{"error": "usage: svgstegDiffPixels(aRGBA, bRGBA, w, h)"}
	}
	w, h := args[2].Int(), args[3].Int()
	if w <= 0 || h <= 0 {
		return map[string]any{"error": "w and h must be positive"}
	}
	a := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(a, args[0])
	b := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(b, args[1])
	if need := w * h * 4; len(a) < need || len(b) < need {
		return map[string]any{"error": "buffer smaller than w*h*4"}
	}
	changed, maxD, mean := diffPixels(a, b, w, h)
	total := w * h
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(changed) / float64(total)
	}
	return map[string]any{"changed": changed, "total": total, "changedPct": pct, "maxDelta": int(maxD), "meanDelta": mean}
}
