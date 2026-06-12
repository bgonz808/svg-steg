//go:build !js && !norender

package main

import "testing"

// FuzzRenderSVGBuiltinOKSVG drives malformed/random SVG into the unaudited oksvg
// renderer and asserts it never panics (the in-function recover must convert any
// oksvg panic into an error) and never hangs the harness. This is the boundary
// fuzz target for the untrusted-input parser (BACKLOG T-004).
//
// Run:  go test -run=NONE -fuzz=FuzzRenderSVGBuiltinOKSVG -fuzztime=60s
func FuzzRenderSVGBuiltinOKSVG(f *testing.F) {
	seeds := []string{
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path d="M0 0 L10 10"/></svg>`,
		`<svg></svg>`,
		``,
		`<svg viewBox="0 0 1 1"><path d="`, // truncated path
		`<svg xmlns="http://www.w3.org/2000/svg"><rect width="5" height="5"/></svg>`,
		`<svg viewBox="0 0 1 1"><path d="M0 0` + "\x00\x00" + `"/></svg>`, // NUL bytes
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxSVGBytes {
			t.Skip() // mirror the production size cap
		}
		// Must not panic; an error return is fine. recover() inside
		// renderSVGBuiltinOKSVG should convert any oksvg panic into an error, so
		// a panic that escapes to here means the containment failed — a real bug.
		_, _ = renderSVGBuiltinOKSVG(data, 64, 64)
	})
}
