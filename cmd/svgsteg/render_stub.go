//go:build js || norender

// Renderer-free stubs for GOOS=js (the browser rasterizes via <canvas>) and `-tags
// norender` (reduced footprint — links none of oksvg/image/x-image). rendererBuiltIn=false
// drives front-door feature-gating in validateOpt; these stubs are the fail-closed
// backstop — a skipped check is conveyed, never silently treated as a pass. See T-040.

package main

import (
	"errors"
	"fmt"
	"io"
)

const rendererBuiltIn = false

// errNoRenderer is returned by every renderer-dependent path in this build.
var errNoRenderer = errors.New("the SVG renderer is not built in (GOOS=js or -tags norender); rebuild without -tags norender for visual diffing/fidelity checks")

func cmdDiff(args []string) error {
	return errNoRenderer
}

func diffSVGBytes(aSVG, bSVG []byte, renderer string, maxCanvas int, amplify int) (DiffStats, error) {
	return DiffStats{}, errNoRenderer
}

func emitEncodeSidecars(originalSVG, encodedSVG []byte, opt options, logw io.Writer) error {
	if opt.emitSidecars {
		fmt.Fprintln(logw, "sidecars skipped: renderer not built in (-tags norender)")
	}
	return nil
}

// auditDistortion is unavailable without a rasterizer. ok=false signals "not measured" —
// callers MUST report UNAVAILABLE and never treat the zero values as a 0%-distortion pass.
func auditDistortion(input, output []byte) (changedPct float64, maxDelta uint8, meanDelta float64, ok bool) {
	return 0, 0, 0, false
}
