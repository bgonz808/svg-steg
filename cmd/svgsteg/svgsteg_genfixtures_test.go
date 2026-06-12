package main

import (
	"fmt"
	"strings"
)

// Synthetic SVG "document classes" for the detectors and the capacity-vs-stealth
// sweep. All generated deterministically and test-only — nothing is committed to
// the repo (keeps it small) and nothing ships in the binary. Real-world tool
// exports (for source-plausibility/formatting tests) belong in testdata/ later;
// those quirks can't be synthesized. See ticket T-017 (per-tool corpus).

// genSVG builds a single-path SVG with `points` coordinate pairs. Each coordinate
// has exactly `decimals` fractional digits (non-integer, varied -> eligible
// carrier), integer parts spread across [0,intRange), on a viewBox of viewW x viewH.
func genSVG(points int, viewW, viewH float64, decimals, intRange int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %g %g"><path d="M `, viewW, viewH)
	p10 := 1
	for range decimals {
		p10 *= 10
	}
	if intRange < 1 {
		intRange = 1
	}
	for i := range points {
		if i > 0 {
			b.WriteString(" L ")
		}
		writeGenNum(&b, (i*7)%intRange, (i*7919)%p10, decimals)
		b.WriteByte(' ')
		writeGenNum(&b, (i*13+1)%intRange, (i*104729+3)%p10, decimals)
	}
	b.WriteString(`" fill="none" stroke="black"/></svg>`)
	return []byte(b.String())
}

func writeGenNum(b *strings.Builder, intPart, frac, decimals int) {
	if decimals <= 0 {
		fmt.Fprintf(b, "%d", intPart)
		return
	}
	if frac == 0 {
		frac = 1 // avoid an exactly-integer coordinate
	}
	fmt.Fprintf(b, "%d.%0*d", intPart, decimals, frac)
}

type svgClass struct {
	name string
	svg  []byte
}

// svgClasses returns the synthetic document classes swept by the benchmark — spanning
// density, natural precision, and canvas scale (the axes that move capacity & stealth).
func svgClasses() []svgClass {
	base := []svgClass{
		{"sparse-3dec", genSVG(40, 512, 512, 3, 500)},
		{"dense-3dec", genSVG(2000, 512, 512, 3, 500)},
		{"lowprec-1dec", genSVG(600, 512, 512, 1, 500)},
		{"highprec-5dec", genSVG(600, 512, 512, 5, 500)},
		{"smallcanvas-3dec", genSVG(600, 10, 10, 3, 9)},
		{"largecanvas-3dec", genSVG(600, 100000, 100000, 3, 90000)},
	}
	return append(base, archetypeClasses()...)
}

// StyleSpec parametrizes the formatting of a generated SVG (separators, number style,
// command case, layout) so fixtures can mimic how real tools format their exports. The
// path geometry comes from a seed.
type StyleSpec struct {
	Name        string
	ViewW       int
	ViewH       int
	Decimals    int
	Comma       bool   // comma vs space separator
	LeadingZero bool   // 0.5 vs .5
	Relative    bool   // l/m vs L/M commands
	Minified    bool   // single line vs pretty
	Indent      string // when pretty
	SelfClose   bool   // /> vs ></path>
}

func styledNum(intp, frac, decimals int, leadingZero bool) string {
	if decimals <= 0 {
		return fmt.Sprintf("%d", intp)
	}
	if frac == 0 {
		frac = 1 // avoid an integer-like coordinate
	}
	num := fmt.Sprintf("%d.%0*d", intp, decimals, frac)
	if intp == 0 && !leadingZero {
		num = num[1:] // 0.137 -> .137
	}
	return num
}

func genStyledSVG(s StyleSpec, points, seed int) []byte {
	sep := " "
	if s.Comma {
		sep = ","
	}
	mCmd, lCmd := "M", "L"
	if s.Relative {
		mCmd, lCmd = "m", "l"
	}
	p10 := 1
	for range s.Decimals {
		p10 *= 10
	}
	var d strings.Builder
	d.WriteString(mCmd)
	for i := range points {
		intp := (i * 7) % max(s.ViewW, 1)
		if i%5 == 0 {
			intp = 0 // sub-1 coord, exercises leading-zero style
		}
		yint := (i * 13) % max(s.ViewH, 1)
		if i%7 == 0 {
			yint = 0
		}
		x := styledNum(intp, (seed*7919+i*31)%p10, s.Decimals, s.LeadingZero)
		y := styledNum(yint, (seed*104729+i*53)%p10, s.Decimals, s.LeadingZero)
		if i > 0 {
			d.WriteString(lCmd)
		}
		d.WriteString(x + sep + y)
	}
	pathClose := "/>"
	if !s.SelfClose {
		pathClose = "></path>"
	}
	var b strings.Builder
	if s.Minified {
		fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d"><path d="%s"%s</svg>`,
			s.ViewW, s.ViewH, d.String(), pathClose)
	} else {
		fmt.Fprintf(&b, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 %d %d\">\n%s<path d=\"%s\"%s\n</svg>\n",
			s.ViewW, s.ViewH, s.Indent, d.String(), pathClose)
	}
	return []byte(b.String())
}

// archetypeClasses emits the generated polyline in three export formatting archetypes.
func archetypeClasses() []svgClass {
	specs := []StyleSpec{
		{Name: "arch-svgo-min", ViewW: 268, ViewH: 96, Decimals: 2, Comma: true, LeadingZero: false, Relative: true, Minified: true, SelfClose: false},
		{Name: "arch-figma-pretty", ViewW: 24, ViewH: 24, Decimals: 3, Comma: true, LeadingZero: true, Relative: false, Minified: false, Indent: "  ", SelfClose: true},
		{Name: "arch-hiprec-abs", ViewW: 419, ViewH: 419, Decimals: 4, Comma: true, LeadingZero: true, Relative: false, Minified: false, Indent: "\t", SelfClose: true},
	}
	out := make([]svgClass, 0, len(specs))
	for _, s := range specs {
		out = append(out, svgClass{s.Name, genStyledSVG(s, 400, 42)})
	}
	return out
}
