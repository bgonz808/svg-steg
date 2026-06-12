package main

import "testing"

// Synthetic archetype style fixtures (test-only).

const svgoArchetype = `<svg viewBox="0 0 100 100"><path d="M.5,1.5c.3,.4,.7,.9,1.2,1.5h2v-3z"/></svg>`

const inkscapeArchetype = `<svg xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" viewBox="0 0 100 100">
  <!-- Created with Inkscape -->
  <defs id="defs1" />
  <g id="layer1" style="fill:#000">
    <path id="path1" d="M 10.5,20.5 L 30.5,40.5 Z" />
    <path id="path2" d="M 1.0,2.0 L 3.0,4.0 Z" />
  </g>
</svg>`

const figmaArchetype = `<svg viewBox="0 0 24 24"><path d="M12 2L22 22" fill="black" /></svg>`

func TestAnalyzeXMLStyle(t *testing.T) {
	p := analyzeXMLStyle(svgoArchetype)
	if p.Indent != "minified" {
		t.Errorf("svgo: Indent = %q, want minified", p.Indent)
	}
	if p.LeadingZero {
		t.Errorf("svgo: LeadingZero = true, want false (.5 style)")
	}
	if !p.RelativeCmds {
		t.Errorf("svgo: RelativeCmds = false, want true")
	}
	if !p.SeparatorComma {
		t.Errorf("svgo: SeparatorComma = false, want true")
	}

	ink := analyzeXMLStyle(inkscapeArchetype)
	if ink.Indent != "spaces" {
		t.Errorf("inkscape: Indent = %q, want spaces", ink.Indent)
	}
	if !ink.HasDefs || !ink.HasGroups {
		t.Errorf("inkscape: HasDefs=%v HasGroups=%v, want both true", ink.HasDefs, ink.HasGroups)
	}
	if ink.ViewBoxKind != "integer" {
		t.Errorf("inkscape: ViewBoxKind = %q, want integer", ink.ViewBoxKind)
	}
	if len(ink.Fingerprints) == 0 {
		t.Errorf("inkscape: expected fingerprints, got none")
	}
}

func TestClassifyViewBox(t *testing.T) {
	cases := map[string]string{
		"0 0 382 382":      "integer",
		"0 0 267.64 96.13": "decimal",
		"-81.5 0 419 419":  "negative-origin",
	}
	for vb, want := range cases {
		if got := classifyViewBox(vb); got != want {
			t.Errorf("classifyViewBox(%q) = %q, want %q", vb, got, want)
		}
	}
}

// TestArchetypeGenerators verifies the copyright-safe generators reproduce the
// intended source STYLE (so analyzeXMLStyle reads them as the real exports would).
func TestArchetypeGenerators(t *testing.T) {
	var svgo svgClass
	for _, c := range archetypeClasses() {
		p := analyzeXMLStyle(string(c.svg))
		t.Logf("%-18s indent=%-8s comma=%-5v leadZero=%-5v rel=%-5v selfClose=%v vb=%s",
			c.name, p.Indent, p.SeparatorComma, p.LeadingZero, p.RelativeCmds, p.SelfClose, p.ViewBoxKind)
		if c.name == "arch-svgo-min" {
			svgo = c
		}
	}
	p := analyzeXMLStyle(string(svgo.svg))
	if p.Indent != "minified" || !p.SeparatorComma || p.LeadingZero || !p.RelativeCmds {
		t.Errorf("svgo archetype mis-styled: indent=%s comma=%v leadZero=%v rel=%v",
			p.Indent, p.SeparatorComma, p.LeadingZero, p.RelativeCmds)
	}
}

func TestDetectSVGTool(t *testing.T) {
	cases := []struct {
		name string
		svg  string
		want string
	}{
		{"inkscape-explicit", inkscapeArchetype, "inkscape"},
		{"svgo-inferred", svgoArchetype, "svgo-optimized"},
		{"figma-inferred", figmaArchetype, "figma-like"},
	}
	for _, c := range cases {
		got := detectSVGTool(c.svg, analyzeXMLStyle(c.svg))
		if got != c.want {
			t.Errorf("%s: detectSVGTool = %q, want %q", c.name, got, c.want)
		}
	}
}
