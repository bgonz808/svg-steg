package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// DETECT layer ("eyeball detector"): pure, read-only measurements of an SVG's
// path-coordinate precision style. These form the objective function the stealth
// strategies (T-028, T-032) optimize against. Nothing here mutates the SVG.
//
// Scope: NUMERIC-STYLE detectors only (the carrier-specific, highest-leverage
// group). XML-shape, carrier-distribution, growth, and fingerprint detectors are
// separate groups (see BACKLOG). The canvas-relative precision-FLOOR detector
// (free-bit budget) is intentionally deferred to the lossyWAV research pass.

// decimalCount returns the number of fractional digits in a numeric token.
func decimalCount(tok string) int {
	dot := strings.IndexByte(tok, '.')
	if dot < 0 {
		return 0
	}
	n := 0
	for i := dot + 1; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			break
		}
		n++
	}
	return n
}

// pathNumbers returns every numeric token across all <path d="..."> in document order.
func pathNumbers(svg string) []string {
	var out []string
	for _, m := range pathDRe.FindAllStringSubmatch(svg, -1) {
		d := pathDFromMatch(m)
		out = append(out, numberRe.FindAllString(d, -1)...)
	}
	return out
}

// NumericStyleProfile summarizes coordinate precision style + detectability tells.
// Each *Frac field is in [0,1].
type NumericStyleProfile struct {
	Count          int
	MedianDecimals int
	P90Decimals    int
	MaxDecimals    int
	ModeDecimals   int

	UniformWidthFrac   float64 // fraction at the modal decimal width (regularity)
	HighPrecisionFrac  float64 // fraction with decimals > median+1 (the additive tell)
	IntraPointAsymFrac float64 // fraction of (x,y) pairs with |dec(x)-dec(y)| >= 2
}

func percentileInt(sorted []int, p float64) int {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// analyzeNumericStyle computes the precision profile + tells from path coordinates.
func analyzeNumericStyle(svg string) NumericStyleProfile {
	nums := pathNumbers(svg)
	var prof NumericStyleProfile
	prof.Count = len(nums)
	if len(nums) == 0 {
		return prof
	}

	decs := make([]int, len(nums))
	freq := map[int]int{}
	for i, t := range nums {
		d := decimalCount(t)
		decs[i] = d
		freq[d]++
	}

	sorted := append([]int(nil), decs...)
	sort.Ints(sorted)
	prof.MedianDecimals = percentileInt(sorted, 0.5)
	prof.P90Decimals = percentileInt(sorted, 0.9)
	prof.MaxDecimals = sorted[len(sorted)-1]

	// modal width (ties resolved toward the smaller width)
	bestD, bestN := 0, -1
	for d, n := range freq {
		if n > bestN || (n == bestN && d < bestD) {
			bestD, bestN = d, n
		}
	}
	prof.ModeDecimals = bestD
	prof.UniformWidthFrac = float64(bestN) / float64(len(decs))

	hp := 0
	for _, d := range decs {
		if d > prof.MedianDecimals+1 {
			hp++
		}
	}
	prof.HighPrecisionFrac = float64(hp) / float64(len(decs))

	// intra-point asymmetry (approx: pair consecutive numbers as x,y — exact for
	// M/L/T/C/S/Q runs, approximate for H/V/A; refine with a path tokenizer later)
	pairs, asym := 0, 0
	for i := 0; i+1 < len(decs); i += 2 {
		pairs++
		diff := decs[i] - decs[i+1]
		if diff < 0 {
			diff = -diff
		}
		if diff >= 2 {
			asym++
		}
	}
	if pairs > 0 {
		prof.IntraPointAsymFrac = float64(asym) / float64(pairs)
	}
	return prof
}

// numericSuspicionScore composes the tells into a 0..100 "eyeball detector" score.
// Higher = more obviously machine-modified / weird precision. This is a heuristic
// objective function (deliberately conservative), NOT a steganalysis verdict: it
// targets the human/inspection tell (anomalous precision), not low-digit entropy.
func numericSuspicionScore(p NumericStyleProfile) int {
	if p.Count == 0 {
		return 0
	}
	score := 0.0
	score += 70 * p.HighPrecisionFrac  // coords with anomalously many decimals (dominant tell)
	score += 20 * p.IntraPointAsymFrac // lopsided x/y precision within a point

	if spread := float64(p.MaxDecimals - p.MedianDecimals); spread > 2 {
		s := (spread - 2) / 4
		if s > 1 {
			s = 1
		}
		score += 10 * s // precision inflation vs the document's typical width
	}

	if score > 100 {
		score = 100
	}
	return int(score + 0.5)
}

// meaningfulDecimals returns how many fractional decimal places of a coordinate are
// visually significant when the viewBox spans vbExtent user units along an axis and
// the document is rendered at renderPx device pixels along that axis, given a
// sub-pixel visibility threshold subPixelPx. Digits beyond this are the "free" budget
// the perceptual-substitutive carrier model embeds into (T-012 research
// finding 2 — verified 3-0 against w3.org SVG coords). Derivation: scale
// S = renderPx/vbExtent device-px per user-unit; a digit at decimal position d
// displaces 10^-d * S device px, visible iff that >= subPixelPx, i.e. d <= log10(S/subPixelPx).
func meaningfulDecimals(vbExtent, renderPx, subPixelPx float64) int {
	if vbExtent <= 0 || renderPx <= 0 || subPixelPx <= 0 {
		return 0
	}
	d := math.Floor(math.Log10((renderPx / vbExtent) / subPixelPx))
	if math.IsInf(d, 0) || math.IsNaN(d) || d < 0 {
		return 0
	}
	return int(d)
}

// CanvasPrecisionStats reports how many path coordinates carry precision beyond the
// canvas-justified visual floor — decimals that are visually meaningless at the given
// render resolution. That excess is exactly the additive-carrier tell made
// canvas-relative, and (inverted) the free-bit budget for the perceptual model.
type CanvasPrecisionStats struct {
	MeaningfulDecimals int
	Count              int
	OverFloorCount     int // coords with more decimals than meaningful
	OverFloorFrac      float64
	WastedDigits       int // total visually-dead decimal digits present (the free budget)
}

// analyzeCanvasPrecision uses the SMALLER viewBox extent (highest scale → most
// meaningful decimals → most conservative flagging, fewest false positives).
func analyzeCanvasPrecision(svg string, renderPx, subPixelPx float64) CanvasPrecisionStats {
	var st CanvasPrecisionStats
	vb := parseViewBox(svg)
	if !vb.Found || vb.Width <= 0 || vb.Height <= 0 {
		return st
	}
	extent := vb.Width
	if vb.Height < extent {
		extent = vb.Height
	}
	st.MeaningfulDecimals = meaningfulDecimals(extent, renderPx, subPixelPx)

	nums := pathNumbers(svg)
	st.Count = len(nums)
	for _, t := range nums {
		if over := decimalCount(t) - st.MeaningfulDecimals; over > 0 {
			st.OverFloorCount++
			st.WastedDigits += over
		}
	}
	if st.Count > 0 {
		st.OverFloorFrac = float64(st.OverFloorCount) / float64(st.Count)
	}
	return st
}

// --- XML-syntax / source archetype detector (axis 2; T-015) ---
// Read-only. Measures how an SVG's *source text* is shaped (formatting, number
// style, structure) so inserted carriers can mimic it, and so we never emit a
// tool fingerprint. Complements the numeric (axis 3) and canvas-precision detectors.

var (
	tagRe        = regexp.MustCompile(`<([A-Za-z][\w:-]*)`)
	xmlViewBoxRe = regexp.MustCompile(`viewBox\s*=\s*["']([^"']+)["']`)
)

// XMLStyleProfile is the source-shape archetype of an SVG.
type XMLStyleProfile struct {
	Indent        string // "tabs" | "spaces" | "minified"
	QuoteChar     byte   // '"' or '\''
	SelfClose     bool   // /> preferred over ></tag>
	MaxLineLen    int
	MedianLineLen int

	SeparatorComma bool // comma-dominant path number separators
	LeadingZero    bool // 0.5 vs .5
	RelativeCmds   bool // relative path commands dominate

	Tags           map[string]int
	HasDefs        bool
	HasGroups      bool
	IDCount        int
	StyleAttrCount int
	ViewBoxKind    string // integer | decimal | negative-origin | absent
	Fingerprints   []string
}

func isPathCmd(b byte) bool {
	switch b {
	case 'M', 'L', 'H', 'V', 'C', 'S', 'Q', 'T', 'A', 'Z',
		'm', 'l', 'h', 'v', 'c', 's', 'q', 't', 'a', 'z':
		return true
	}
	return false
}

func isCoordChar(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '+'
}

// classifyViewBox tags a viewBox value string by its numeric style.
func classifyViewBox(s string) string {
	neg, dec := false, false
	for _, f := range strings.Fields(strings.ReplaceAll(s, ",", " ")) {
		if strings.HasPrefix(f, "-") {
			neg = true
		}
		if strings.Contains(f, ".") {
			dec = true
		}
	}
	switch {
	case neg:
		return "negative-origin"
	case dec:
		return "decimal"
	default:
		return "integer"
	}
}

func lineMaxMedian(lens []int) (int, int) {
	if len(lens) == 0 {
		return 0, 0
	}
	s := append([]int(nil), lens...)
	sort.Ints(s)
	return s[len(s)-1], s[len(s)/2]
}

// analyzeXMLStyle extracts the source-shape archetype from an SVG.
func analyzeXMLStyle(svg string) XMLStyleProfile {
	var p XMLStyleProfile
	p.Tags = map[string]int{}
	for _, m := range tagRe.FindAllStringSubmatch(svg, -1) {
		p.Tags[m[1]]++
	}
	p.HasDefs = p.Tags["defs"] > 0
	p.HasGroups = p.Tags["g"] > 0
	p.IDCount = strings.Count(svg, " id=")
	p.StyleAttrCount = strings.Count(svg, " style=")

	if strings.Count(svg, `='`) > strings.Count(svg, `="`) {
		p.QuoteChar = '\''
	} else {
		p.QuoteChar = '"'
	}
	p.SelfClose = strings.Count(svg, "/>") >= strings.Count(svg, "></")

	lines := strings.Split(svg, "\n")
	lens := make([]int, len(lines))
	tabs, spaces := 0, 0
	for i, l := range lines {
		lens[i] = len(l)
		t := strings.TrimLeft(l, " \t")
		if t == "" {
			continue
		}
		lead := l[:len(l)-len(t)]
		if strings.Contains(lead, "\t") {
			tabs++
		} else if lead != "" {
			spaces++
		}
	}
	p.MaxLineLen, p.MedianLineLen = lineMaxMedian(lens)
	switch {
	case len(lines) <= 2:
		p.Indent = "minified"
	case tabs > spaces:
		p.Indent = "tabs"
	case spaces > 0:
		p.Indent = "spaces"
	default:
		p.Indent = "minified"
	}

	if vb := xmlViewBoxRe.FindStringSubmatch(svg); vb != nil {
		p.ViewBoxKind = classifyViewBox(vb[1])
	} else {
		p.ViewBoxKind = "absent"
	}

	comma, space, lead0, noLead, rel, abs := 0, 0, 0, 0, 0, 0
	for _, m := range pathDRe.FindAllStringSubmatch(svg, -1) {
		d := pathDFromMatch(m)
		comma += strings.Count(d, ",")
		for i := range len(d) {
			c := d[i]
			if c >= 'a' && c <= 'z' && isPathCmd(c) {
				rel++
			} else if c >= 'A' && c <= 'Z' && isPathCmd(c) {
				abs++
			}
			if c == ' ' && i > 0 && i+1 < len(d) && isCoordChar(d[i-1]) && isCoordChar(d[i+1]) {
				space++
			}
		}
		for _, t := range numberRe.FindAllString(d, -1) {
			s := strings.TrimPrefix(t, "-")
			if strings.HasPrefix(s, "0.") {
				lead0++
			} else if strings.HasPrefix(s, ".") {
				noLead++
			}
		}
	}
	p.SeparatorComma = comma >= space
	p.LeadingZero = lead0 >= noLead
	p.RelativeCmds = rel > abs

	low := strings.ToLower(svg)
	for _, f := range []string{"adobe", "illustrator", "inkscape", "figma", "sketch", "svgo", "coreldraw", "affinity", "matplotlib", "generator", "created with", "svgsteg"} {
		if strings.Contains(low, f) {
			p.Fingerprints = append(p.Fingerprints, f)
		}
	}
	return p
}

// detectSVGTool guesses the originating editor — explicit fingerprints first, then
// style inference (which still works when an optimizer stripped the comment).
func detectSVGTool(svg string, p XMLStyleProfile) string {
	low := strings.ToLower(svg)
	switch {
	case strings.Contains(low, "inkscape"):
		return "inkscape"
	case strings.Contains(low, "illustrator") || strings.Contains(low, "adobe"):
		return "illustrator"
	case strings.Contains(low, "created with sketch"):
		return "sketch"
	case strings.Contains(low, "matplotlib"):
		return "matplotlib"
	case strings.Contains(low, "coreldraw"):
		return "coreldraw"
	}
	// fingerprint stripped — infer from style archetype
	switch {
	case p.Indent == "minified" && !p.LeadingZero && p.RelativeCmds:
		return "svgo-optimized"
	case p.HasDefs && p.HasGroups && p.IDCount > 5 && p.StyleAttrCount > 0:
		return "inkscape-like"
	case p.SelfClose && p.ViewBoxKind == "integer":
		return "figma-like"
	}
	return "unknown"
}

// --- text-line-length anomaly detector (axis 2): treat the SVG as a text file ---
// A single "blob" line dramatically longer than the body (e.g. an 11KB line among
// 200-char lines) is a glaring machine-insertion tell, independent of rendering.
// Additive embedding grows lines uniformly (no outlier); this guards the invasive
// Tier-3/fallback insertion modes that CAN create blob lines (T-028).

type LineLengthStats struct {
	Lines      int
	Median     int
	P90        int
	Max        int
	MaxOverP90 float64 // outlier ratio — a lone blob line spikes this
	BlobLines  int     // lines far above the body: > max(P90*4, 1000)
}

func analyzeLineLengths(svg string) LineLengthStats {
	var st LineLengthStats
	lines := strings.Split(svg, "\n")
	st.Lines = len(lines)
	if len(lines) == 0 {
		return st
	}
	lens := make([]int, len(lines))
	for i, l := range lines {
		lens[i] = len(l)
	}
	sorted := append([]int(nil), lens...)
	sort.Ints(sorted)
	st.Median = percentileInt(sorted, 0.5)
	st.P90 = percentileInt(sorted, 0.9)
	st.Max = sorted[len(sorted)-1]
	if st.P90 > 0 {
		st.MaxOverP90 = float64(st.Max) / float64(st.P90)
	}
	blobThresh := max(st.P90*4, 1000)
	for _, n := range lens {
		if n > blobThresh {
			st.BlobLines++
		}
	}
	return st
}

// lineLengthBudget is the longest plausible line for an output given the source's
// P90 line length: max(p90*2, 240). It is RELATIVE to the source on purpose — a
// minified SVG legitimately has very long lines, so no absolute cap (a 1600 cap
// would false-flag minified inputs). Outliers relative to the body are caught
// separately by the blob detector (P90*4). An output Max above this is suspicious.
func lineLengthBudget(sourceP90 int) int {
	return max(sourceP90*2, 240)
}

// --- composite post-processing stealth gate (T-018) ---
// Layered defense: after encode, compare output vs input across all axes and flag
// anything that would look suspicious. This is the STEALTH analog of the encode-time
// round-trip CORRECTNESS self-check (verifyEncodeRoundtrip / T-010). Pass=false on a
// HARD tell (blob line, line over budget, a 'svgsteg' fingerprint); softer issues
// (rising precision suspicion, style drift) are surfaced as warnings, not failures.

type SourcePlausibilityReport struct {
	NumericSuspicion      int      // axis-3 distribution suspicion of the output
	NumericSuspicionDelta int      // output - input
	CanvasWastedAvg       float64  // axis-3 canvas-relative: avg over-floor digits/coord
	OutputBlobLines       int      // axis-2: blob lines in output
	MaxLineOverBudget     bool     // axis-2: output max line > source-derived budget
	StyleDrift            []string // axis-2: style dimensions that diverged from input
	OutputFingerprints    []string // tool fingerprints present in output
	Warnings              []string
	Pass                  bool
}

func analyzeSourcePlausibility(input, output string, renderPx, subPx float64) SourcePlausibilityReport {
	var r SourcePlausibilityReport

	inNum := numericSuspicionScore(analyzeNumericStyle(input))
	r.NumericSuspicion = numericSuspicionScore(analyzeNumericStyle(output))
	r.NumericSuspicionDelta = r.NumericSuspicion - inNum

	if cp := analyzeCanvasPrecision(output, renderPx, subPx); cp.Count > 0 {
		r.CanvasWastedAvg = float64(cp.WastedDigits) / float64(cp.Count)
	}

	inLL, outLL := analyzeLineLengths(input), analyzeLineLengths(output)
	r.OutputBlobLines = outLL.BlobLines
	budget := lineLengthBudget(inLL.P90)
	r.MaxLineOverBudget = outLL.Max > budget

	inStyle, outStyle := analyzeXMLStyle(input), analyzeXMLStyle(output)
	r.StyleDrift = styleDrift(inStyle, outStyle)
	r.OutputFingerprints = outStyle.Fingerprints

	hasSvgsteg := false
	for _, f := range r.OutputFingerprints {
		if f == "svgsteg" {
			hasSvgsteg = true
		}
	}

	if r.NumericSuspicionDelta >= 15 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("precision suspicion rose %d (in %d -> out %d)", r.NumericSuspicionDelta, inNum, r.NumericSuspicion))
	}
	if r.OutputBlobLines > inLL.BlobLines {
		r.Warnings = append(r.Warnings, fmt.Sprintf("introduced %d blob line(s)", r.OutputBlobLines-inLL.BlobLines))
	}
	if r.MaxLineOverBudget {
		r.Warnings = append(r.Warnings, fmt.Sprintf("max line %d exceeds source budget %d", outLL.Max, budget))
	}
	if hasSvgsteg {
		r.Warnings = append(r.Warnings, "output contains a 'svgsteg' fingerprint")
	}
	if len(r.StyleDrift) > 0 {
		r.Warnings = append(r.Warnings, "style drift vs source: "+strings.Join(r.StyleDrift, ", "))
	}

	// Hard gate: never ship a blob line, an over-budget line, or a self fingerprint.
	r.Pass = r.OutputBlobLines <= inLL.BlobLines && !r.MaxLineOverBudget && !hasSvgsteg
	return r
}

func styleDrift(a, b XMLStyleProfile) []string {
	var d []string
	if a.SeparatorComma != b.SeparatorComma {
		d = append(d, "separator")
	}
	if a.LeadingZero != b.LeadingZero {
		d = append(d, "leading-zero")
	}
	if a.SelfClose != b.SelfClose {
		d = append(d, "self-close")
	}
	if a.RelativeCmds != b.RelativeCmds {
		d = append(d, "command-case")
	}
	if a.Indent != b.Indent {
		d = append(d, "indent")
	}
	return d
}

// --- per-encode composite analysis (T-019): single source of truth ---
// PRODUCTION code. The tool (future `encode --source-check` / `inspect`) AND the
// test sweep both consume this, so the test validates exactly what the tool reports.
// It composes the stealth detectors (via analyzeSourcePlausibility) with the
// size/compression efficiency math.

type EncodeAnalysis struct {
	InputBytes       int
	OutputBytes      int
	PayloadBytes     int
	CompressionMode  string
	CompressedBytes  int
	CompressionRatio float64 // compressed / payload — the compression gain
	Bloat            float64 // (out - in) / payload — SVG growth per payload byte (steg-ideal: 0)
	Overhead         float64 // bloat - 1 — non-payload growth per byte; CAN go negative purely via compression
	SizeGrowthPct    float64 // (out - in) / in * 100 — the file-size tell

	// Raw / physical view — compression-independent. StreamBytes is the actual data
	// embedded (compressed+framed[+encrypted]); CarrierExpansion = SVG growth per RAW
	// embedded byte (the true carrier-mechanism cost; always > 0; additive ~3,
	// substitutive ~0). Unlike Overhead, this never goes negative via compression.
	StreamBytes      int
	CarrierExpansion float64

	Plausibility SourcePlausibilityReport // the 3-axis stealth composite
}

// analyzeEncode computes the full per-encode metric row from the input/output SVGs,
// the payload, and the encoder's stats. renderPx/subPx parameterize the canvas-
// relative precision axis (see meaningfulDecimals).
func analyzeEncode(input, output, payload []byte, stats EncodeStats, renderPx, subPx float64) EncodeAnalysis {
	var a EncodeAnalysis
	a.InputBytes = len(input)
	a.OutputBytes = len(output)
	a.PayloadBytes = len(payload)
	a.CompressionMode = stats.CompressionMode
	a.CompressedBytes = stats.CompressedBytes

	grow := float64(a.OutputBytes - a.InputBytes)
	if a.PayloadBytes > 0 {
		a.Bloat = grow / float64(a.PayloadBytes)
		a.Overhead = a.Bloat - 1
		a.CompressionRatio = float64(a.CompressedBytes) / float64(a.PayloadBytes)
	}
	if a.InputBytes > 0 {
		a.SizeGrowthPct = 100 * grow / float64(a.InputBytes)
	}
	a.StreamBytes = stats.StreamBytes
	if a.StreamBytes > 0 {
		a.CarrierExpansion = grow / float64(a.StreamBytes) // compression-independent carrier cost
	}
	a.Plausibility = analyzeSourcePlausibility(string(input), string(output), renderPx, subPx)
	return a
}

// auditDistortion (the renderer-backed distortion measure, axis 1) lives in
// render_native.go; render_stub.go provides the renderer-free fallback.
