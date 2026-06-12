package main

/*
svgsteg.go - Single-file SVG path-coordinate binary steganography prototype

PURPOSE
  svgsteg embeds arbitrary binary data into SVG <path d="..."> numeric coordinates
  and recovers the exact original bytes. It is a research/provenance/watermarking
  prototype for owned files and controlled challenges.

CORE IDEA
  Coordinates are normalized to a visible precision floor. The next 3 decimal
  digits are used as a byte carrier. Example with visible precision 3:

      42.137 + byte(65) -> 42.137065

  v2 adds a carrier eligibility model so clean integers and obvious grid values
  are skipped by default. It also has optional true geometry-preserving capacity
  expansion via path subdivision:

      line segment  -> multiple collinear line segments
      cubic Bézier  -> multiple equivalent cubics via De Casteljau subdivision

  Subdivision is gated behind --subdivide because it adds visible editor handles.
  It should render the same, but a design tool may expose extra vertices/handles.

SECURITY / INTEGRITY
  Payloads are compressed, framed with SHA-256, encrypted and authenticated with
  AES-256-GCM. The key is derived from a passphrase using PBKDF2-HMAC-SHA256
  implemented in this file to avoid external dependencies.

DEPENDENCIES
  Core logic is still one Go source file, but this build imports Go modules for
  Brotli, Zstandard, and optional lightweight SVG rasterization:

      github.com/andybalholm/brotli
      github.com/klauspost/compress/zstd
      github.com/fyne-io/oksvg
      github.com/srwiley/rasterx

  The standard library provides raw DEFLATE/flate. Compression defaults to auto:
  none, flate-fast, flate-default, brotli, zstd-fast, and zstd-default are tried,
  then the smallest pre-encryption representation is selected.

BUILD
  First-time setup when using the Brotli/Zstandard build:

      go mod init svgsteg
      go get github.com/andybalholm/brotli github.com/klauspost/compress/zstd github.com/fyne-io/oksvg github.com/srwiley/rasterx golang.org/x/image golang.org/x/net

  PowerShell / Windows:

      go build -trimpath -ldflags="-s -w" -o svgsteg.exe .\svgsteg.go

  PowerShell / Windows with CGO disabled:

      $env:CGO_ENABLED="0"
      go build -trimpath -ldflags="-s -w" -o svgsteg.exe .\svgsteg.go

  cmd.exe:

      set CGO_ENABLED=0 && go build -trimpath -ldflags="-s -w" -o svgsteg.exe svgsteg.go

  Linux/macOS:

      CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o svgsteg svgsteg.go

USAGE
  Subcommands are verbs. Options belong to the verb.

  Self-test with a size sweep from 16 bytes through 16 KiB. With --in,
  additional carrier-election checks are run against your supplied SVG:

      ./svgsteg self-test
      ./svgsteg self-test --self-test-runs 3
      ./svgsteg self-test --in logo.svg

  Check capacity:

      ./svgsteg capacity --in logo.svg
      ./svgsteg capacity --in logo.svg --subdivide

  Encode arbitrary binary payload. Compression defaults to auto:

      ./svgsteg encode --in logo.svg --payload payload.bin --out logo.steg.svg --passphrase-file pass.txt

  Compression choices:

      --compression auto          try built-in candidates and choose smallest
      --compression none          store payload frame without compression
      --compression flate-fast    raw DEFLATE level 1
      --compression flate-default raw DEFLATE default level
      --compression flate-best    raw DEFLATE level 9, explicit only
      --compression brotli        Brotli moderate level
      --compression zstd-fast     Zstandard fastest
      --compression zstd-default  Zstandard default

  Decode payload:

      ./svgsteg decode --in logo.steg.svg --out recovered.bin --passphrase-file pass.txt
      diff -s payload.bin recovered.bin

  Encode with geometry-preserving subdivision enabled:

      ./svgsteg encode --in logo.svg --payload payload.bin --out logo.steg.svg --passphrase-file pass.txt --subdivide

  If subdivision still cannot provide enough carriers, allow an invisible fallback
  carrier group explicitly:

      ./svgsteg encode ... --subdivide --allow-invisible-carrier

STEALTH / STYLE OPTIONS
  Defaults skip coordinates that look like deliberately clean design values:

      --min-existing-decimals 3
      --skip-integer-like=true
      --skip-simple-fractions=true

  This avoids stuffing values like 4 into 4.000018. Coordinates such as 3.782
  are better carriers because 3.782065 looks more plausible.

NOTES
  - This should be the final step before freezing the SVG.
  - SVG optimizers, path simplifiers, coordinate rounding, and design-tool re-export
    will probably destroy the payload.
  - Visual verification is intentionally deferred to humans or external tooling.
*/

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"math"
	mrand "math/rand"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	outerMagic              = "SGEO2\x00\x00\x01" // 8 bytes
	publicMagic             = "SGEO2PUB"          // 8 bytes; unencrypted integrity-only stream
	innerMagic              = "SVGSTG3!"          // 8 bytes; v3 adds compression mode
	defaultVisiblePrecision = 3
	defaultKDFIterations    = 50000
	carrierDigits           = 3 // one byte encoded as 000-255
)

var (
	pathDRe    = regexp.MustCompile(`(?is)<path\b([^>]*?)\bd\s*=\s*(("([^"]*)")|('([^']*)'))([^>]*)>`)
	numberRe   = regexp.MustCompile(`[+-]?(?:(?:\d+\.\d*)|(?:\.\d+)|(?:\d+))(?:[eE][+-]?\d+)?`)
	svgCloseRe = regexp.MustCompile(`(?is)</svg\s*>`)
	pathLexRe  = regexp.MustCompile(`[AaCcHhLlMmQqSsTtVvZz]|[+-]?(?:(?:\d+\.\d*)|(?:\.\d+)|(?:\d+))(?:[eE][+-]?\d+)?`)
	viewBoxRe  = regexp.MustCompile(`(?is)<svg\b[^>]*\bviewBox\s*=\s*["\']([^"\']*)["\']`)
	widthRe    = regexp.MustCompile(`(?is)<svg\b[^>]*\bwidth\s*=\s*["\']([-+0-9.eE]+)`)
	heightRe   = regexp.MustCompile(`(?is)<svg\b[^>]*\bheight\s*=\s*["\']([-+0-9.eE]+)`)
	attrKVRe   = regexp.MustCompile(`(?is)([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

type options struct {
	inPath                    string
	outPath                   string
	payloadPath               string
	payloadText               string
	noEncrypt                 bool
	passphrase                string
	passphraseFile            string
	visiblePrecision          int
	minExistingDecimals       int
	kdfIterations             int
	compression               string
	verbose                   bool
	skipIntegerLike           bool
	skipSimpleFractions       bool
	integerEpsilon            float64
	integerEpsilonMode        string
	simpleFractionEpsilon     float64
	simpleFractionEpsilonMode string
	fractionDenominators      string
	showMap                   bool
	mapWidth                  int
	subdivide                 bool
	allowInvisibleCarrier     bool
	allowDecimalizeIntegers   bool
	suggest                   bool
	targetBytes               int
	mapMode                   string
	showHistogram             bool
	histWidth                 int
	selfTestRuns              int
	diffAPath                 string
	diffBPath                 string
	diffOutPath               string
	diffRenderer              string
	diffMaxCanvas             int
	diffAmplify               int
	smart                     bool
	visualCheck               bool
	noVerifyRoundtrip         bool
	visualRenderer            string
	visualMaxCanvas           int
	maxChangedPixelsPct       float64
	maxMeanChannelDelta       float64
	maxChannelDelta           int
	smartAllowInvisible       bool
	emitSidecars              bool
	sidecarPrefix             string
	invisibleCarrierStyle     string
}

type viewBoxInfo struct {
	Found                     bool
	MinX, MinY, Width, Height float64
}

type carrierPolicy struct {
	VisiblePrecision          int
	MinExistingDecimals       int
	SkipIntegerLike           bool
	SkipSimpleFractions       bool
	IntegerEpsilon            float64
	SimpleFractionEpsilon     float64
	IntegerEpsilonRaw         float64
	SimpleFractionEpsilonRaw  float64
	IntegerEpsilonMode        string
	SimpleFractionEpsilonMode string
	SimpleFractionDenoms      []int
	AllowDecimalizeIntegers   bool
	InvisibleCarrierStyle     string
	ViewBox                   viewBoxInfo
}

// main() lives in main_cli.go (//go:build !js — the CLI) and main_wasm.go
// (//go:build js — the browser/WASM entry). One package, one main() per build.

func setOptionDefaults(opt *options) {
	opt.visiblePrecision = defaultVisiblePrecision
	opt.minExistingDecimals = 3
	opt.kdfIterations = defaultKDFIterations
	opt.compression = "auto"
	opt.skipIntegerLike = true
	opt.skipSimpleFractions = true
	opt.integerEpsilon = 0.000001
	opt.integerEpsilonMode = "absolute"
	opt.simpleFractionEpsilon = 0.000001
	opt.simpleFractionEpsilonMode = "absolute"
	opt.fractionDenominators = "2,4"
	opt.mapWidth = 40
	opt.mapMode = "dominant"
	opt.histWidth = 32
	opt.selfTestRuns = 2
	opt.diffOutPath = "diff.png"
	opt.diffRenderer = "builtin-oksvg"
	opt.diffMaxCanvas = 512
	opt.diffAmplify = 8
	opt.smart = true
	opt.visualCheck = true
	opt.visualRenderer = "builtin-oksvg"
	opt.visualMaxCanvas = 1024
	// 0.5%: minor pixel deltas stay within renderer AA-difference noise (see parity sweep) and a detector rarely has the original to diff against; structural plausibility governs stealth more than pixel fidelity.
	opt.maxChangedPixelsPct = 0.5
	opt.maxMeanChannelDelta = 0
	opt.maxChannelDelta = 0
	opt.emitSidecars = true
	opt.invisibleCarrierStyle = "defs"
}

func baseFlagSet(name string, opt *options) *flag.FlagSet {
	setOptionDefaults(opt)
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() { printCommandHelp(name) }

	switch name {
	case "encode":
		addEncodeInputFlags(fs, opt)
		addSecurityFlags(fs, opt)
		addCompressionFlags(fs, opt)
		addCarrierPolicyFlags(fs, opt)
		addExpansionFlags(fs, opt)
		addSmartEncodeFlags(fs, opt)
		addVisualBudgetFlags(fs, opt)
		addEncodeOutputFlags(fs, opt)
	case "decode":
		addDecodeInputFlags(fs, opt)
		addSecurityFlags(fs, opt)
		addCarrierPolicyFlags(fs, opt)
	case "capacity":
		addCapacityInputFlags(fs, opt)
		addSecurityModeFlags(fs, opt)
		addCompressionFlags(fs, opt)
		addCarrierPolicyFlags(fs, opt)
		addExpansionFlags(fs, opt)
		addMapHistogramFlags(fs, opt)
		addSuggestFlags(fs, opt)
	case "diff":
		addDiffInputFlags(fs, opt)
		addDiffRendererFlags(fs, opt)
		addVisualBudgetFlags(fs, opt)
	case "self-test", "selftest":
		addSelfTestFlags(fs, opt)
		addSecurityModeFlags(fs, opt)
		addCompressionFlags(fs, opt)
		addCarrierPolicyFlags(fs, opt)
		addExpansionFlags(fs, opt)
	default:
		addEncodeInputFlags(fs, opt)
		addSecurityFlags(fs, opt)
		addCompressionFlags(fs, opt)
		addCarrierPolicyFlags(fs, opt)
		addExpansionFlags(fs, opt)
		addSmartEncodeFlags(fs, opt)
		addVisualBudgetFlags(fs, opt)
		addEncodeOutputFlags(fs, opt)
	}
	return fs
}

func addEncodeInputFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.inPath, "in", "", "input SVG; use - to read SVG from stdin")
	fs.StringVar(&opt.payloadPath, "payload", "", "payload file for encode; use - to read payload from stdin")
	fs.StringVar(&opt.payloadText, "payload-text", "", "UTF-8 text payload for encode; mutually exclusive with --payload")
}

func addDecodeInputFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.inPath, "in", "", "input stego SVG; use - to read SVG from stdin")
	fs.StringVar(&opt.outPath, "out", "", "output recovered payload; use - for stdout")
}

func addCapacityInputFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.inPath, "in", "", "input SVG")
	fs.StringVar(&opt.payloadPath, "payload", "", "optional payload file used to estimate required carrier bytes; use - for stdin")
	fs.StringVar(&opt.payloadText, "payload-text", "", "optional UTF-8 payload text used to estimate required carrier bytes")
}

func addDiffInputFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.diffAPath, "a", "", "first/original SVG input")
	fs.StringVar(&opt.diffBPath, "b", "", "second/encoded SVG input")
	fs.StringVar(&opt.diffOutPath, "diff-out", "diff.png", "output PNG diff path")
}

func addSelfTestFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.inPath, "in", "", "optional real SVG for additional carrier-election checks")
	fs.IntVar(&opt.selfTestRuns, "self-test-runs", 2, "randomized self-test runs per payload size")
}

func addSecurityModeFlags(fs *flag.FlagSet, opt *options) {
	fs.BoolVar(&opt.noEncrypt, "no-encrypt", false, "disable encryption/confidentiality; keep compression and SHA-256 integrity framing; decode can auto-detect this when no passphrase is provided")
}

func addSecurityFlags(fs *flag.FlagSet, opt *options) {
	addSecurityModeFlags(fs, opt)
	fs.StringVar(&opt.passphrase, "passphrase", "", "passphrase; prefer --passphrase-file")
	fs.StringVar(&opt.passphraseFile, "passphrase-file", "", "file containing passphrase")
	fs.IntVar(&opt.kdfIterations, "kdf-iterations", defaultKDFIterations, "PBKDF2-HMAC-SHA256 iterations")
}

func addCompressionFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.compression, "compression", "auto", "compression mode: auto, none, flate-fast, flate-default, flate-best, brotli, zstd-fast, zstd-default")
}

func addCarrierPolicyFlags(fs *flag.FlagSet, opt *options) {
	fs.IntVar(&opt.visiblePrecision, "visible-precision", defaultVisiblePrecision, "visible decimal precision floor")
	fs.IntVar(&opt.minExistingDecimals, "min-existing-decimals", 3, "minimum decimals required for natural carrier eligibility")
	fs.BoolVar(&opt.skipIntegerLike, "skip-integer-like", true, "skip integer/grid-looking values such as 4 or 4.000")
	fs.BoolVar(&opt.skipSimpleFractions, "skip-simple-fractions", true, "skip simple fractional anchors like .000, .250, .500, .750")
	fs.Float64Var(&opt.integerEpsilon, "integer-epsilon", 0.000001, "distance from an integer considered integer-like; interpreted by --integer-epsilon-mode")
	fs.StringVar(&opt.integerEpsilonMode, "integer-epsilon-mode", "absolute", "epsilon mode: absolute, relative-width, relative-height, relative-diagonal, relative-max")
	fs.Float64Var(&opt.simpleFractionEpsilon, "simple-fraction-epsilon", 0.000001, "distance from configured simple fractions considered grid-like; interpreted by --simple-fraction-epsilon-mode")
	fs.StringVar(&opt.simpleFractionEpsilonMode, "simple-fraction-epsilon-mode", "absolute", "epsilon mode: absolute, relative-width, relative-height, relative-diagonal, relative-max")
	fs.StringVar(&opt.fractionDenominators, "simple-fraction-denominators", "2,4", "comma-separated denominators for simple fractions, e.g. 2,4,8")
	fs.BoolVar(&opt.allowDecimalizeIntegers, "allow-decimalize-integers", false, "allow integer tokens like 4 to become 4.000XYZ carriers when min-existing-decimals permits")
}

func addExpansionFlags(fs *flag.FlagSet, opt *options) {
	fs.BoolVar(&opt.subdivide, "subdivide", false, "enable true line/cubic/quadratic path subdivision to add carriers")
	fs.BoolVar(&opt.allowInvisibleCarrier, "allow-invisible-carrier", false, "allow final fallback carrier if capacity is still insufficient")
	fs.StringVar(&opt.invisibleCarrierStyle, "invisible-carrier-style", "defs", "carrier fallback style: defs or opacity; defs avoids literal opacity=0 groups")
}

func addMapHistogramFlags(fs *flag.FlagSet, opt *options) {
	fs.BoolVar(&opt.showMap, "map", false, "print compact Unicode carrier heatmap by hex file offset")
	fs.IntVar(&opt.mapWidth, "map-width", 40, "carrier heatmap cells per line")
	fs.StringVar(&opt.mapMode, "map-mode", "dominant", "carrier map mode: dominant, skipped, eligible, multi")
	fs.BoolVar(&opt.showHistogram, "histogram", false, "print numeric style histograms for path coordinates")
	fs.IntVar(&opt.histWidth, "hist-width", 32, "histogram bar width in characters")
}

func addSuggestFlags(fs *flag.FlagSet, opt *options) {
	fs.BoolVar(&opt.suggest, "suggest", false, "capacity mode: sweep carrier-policy strictness and suggest profiles")
	fs.IntVar(&opt.targetBytes, "target-bytes", 0, "capacity suggestion target in carrier bytes; if --payload is supplied, encrypted stream size is estimated instead")
}

func addSmartEncodeFlags(fs *flag.FlagSet, opt *options) {
	fs.BoolVar(&opt.smart, "smart", true, "automatically try carrier profiles and select the least aggressive profile that passes visual budget")
	fs.BoolVar(&opt.visualCheck, "visual-check", true, "render-diff candidate output before accepting")
	fs.StringVar(&opt.visualRenderer, "visual-renderer", "builtin-oksvg", "visual renderer (in-process oksvg is the only supported backend; flag retained for compatibility)")
	fs.IntVar(&opt.visualMaxCanvas, "visual-max-canvas", 1024, "smart encode visual-check max rendered width/height in pixels")
	fs.BoolVar(&opt.smartAllowInvisible, "smart-allow-invisible", false, "smart encode: allow invisible/fallback carrier profile")
}

func addVisualBudgetFlags(fs *flag.FlagSet, opt *options) {
	fs.Float64Var(&opt.maxChangedPixelsPct, "max-changed-pixels-pct", 0.5, "maximum changed pixels as human percent, e.g. 0.5 means 0.5%; 0 disables")
	fs.Float64Var(&opt.maxMeanChannelDelta, "max-mean-channel-delta", 0, "maximum mean channel delta; 0 disables")
	fs.IntVar(&opt.maxChannelDelta, "max-channel-delta", 0, "maximum per-channel delta; 0 disables")
}

func addDiffRendererFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.diffRenderer, "renderer", "builtin-oksvg", "diff renderer (in-process oksvg is the only supported backend; flag retained for compatibility)")
	fs.IntVar(&opt.diffMaxCanvas, "max-canvas", 512, "diff mode: max rendered width/height in pixels")
	fs.IntVar(&opt.diffAmplify, "diff-amplify", 8, "diff mode: amplify pixel differences by this factor")
}

func addEncodeOutputFlags(fs *flag.FlagSet, opt *options) {
	fs.StringVar(&opt.outPath, "out", "", "output SVG file; use - for stdout")
	fs.BoolVar(&opt.emitSidecars, "sidecars", true, "emit .a.png, .b.png, and .diff.png sidecars next to output SVG when visual rendering is available")
	fs.StringVar(&opt.sidecarPrefix, "sidecar-prefix", "", "sidecar PNG prefix; default is output SVG path without extension")
	fs.BoolVar(&opt.verbose, "verbose", false, "print expanded compression, carrier, and smart-profile accounting")
	fs.BoolVar(&opt.noVerifyRoundtrip, "no-verify-roundtrip", false, "skip the post-encode round-trip recovery self-check (NOT recommended); the check decodes the output in-memory and verifies it recovers the exact payload before writing")
}

func printFlagGroup(title string, register func(*flag.FlagSet, *options)) {
	var opt options
	setOptionDefaults(&opt)
	fs := flag.NewFlagSet(title, flag.ExitOnError)
	var b bytes.Buffer
	fs.SetOutput(&b)
	register(fs, &opt)
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, "%s:\n", title)
	fmt.Fprint(os.Stderr, dashifyLongFlagHelp(b.String()))
	fmt.Fprintln(os.Stderr)
}

func dashifyLongFlagHelp(s string) string {
	lines := strings.SplitAfter(s, "\n")
	for i, line := range lines {
		trim := strings.TrimLeft(line, " \t")
		prefixLen := len(line) - len(trim)
		if strings.HasPrefix(trim, "-") && !strings.HasPrefix(trim, "--") {
			j := 1
			for j < len(trim) {
				c := trim[j]
				if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
					j++
					continue
				}
				break
			}
			if j > 1 {
				lines[i] = line[:prefixLen] + "-" + trim
			}
		}
	}
	return strings.Join(lines, "")
}

func printCommandHelp(name string) {
	switch name {
	case "encode":
		fmt.Fprintln(os.Stderr, "Usage:\n  svgsteg encode --in input.svg --out output.svg (--payload file | --payload-text text | --payload -) [security/options]")
		printFlagGroup("Input / payload", addEncodeInputFlags)
		printFlagGroup("Security", addSecurityFlags)
		printFlagGroup("Compression", addCompressionFlags)
		printFlagGroup("Carrier policy", addCarrierPolicyFlags)
		printFlagGroup("Capacity expansion / fallback", addExpansionFlags)
		printFlagGroup("Smart visual encoding", addSmartEncodeFlags)
		printFlagGroup("Visual budget", addVisualBudgetFlags)
		printFlagGroup("Output / reporting", addEncodeOutputFlags)
	case "decode":
		fmt.Fprintln(os.Stderr, "Usage:\n  svgsteg decode --in encoded.svg --out recovered.bin [security/carrier-policy]")
		printFlagGroup("Input / output", addDecodeInputFlags)
		printFlagGroup("Security", addSecurityFlags)
		printFlagGroup("Carrier policy", addCarrierPolicyFlags)
	case "capacity":
		fmt.Fprintln(os.Stderr, "Usage:\n  svgsteg capacity --in input.svg [analysis/options]")
		printFlagGroup("Input / target estimate", addCapacityInputFlags)
		printFlagGroup("Security mode for estimates", addSecurityModeFlags)
		printFlagGroup("Compression estimate", addCompressionFlags)
		printFlagGroup("Carrier policy", addCarrierPolicyFlags)
		printFlagGroup("Capacity expansion / fallback", addExpansionFlags)
		printFlagGroup("Maps / histograms", addMapHistogramFlags)
		printFlagGroup("Suggestions", addSuggestFlags)
	case "diff":
		fmt.Fprintln(os.Stderr, "Usage:\n  svgsteg diff --a original.svg --b encoded.svg --diff-out diff.png [render/options]")
		printFlagGroup("Inputs / output", addDiffInputFlags)
		printFlagGroup("Renderer", addDiffRendererFlags)
		printFlagGroup("Visual budget", addVisualBudgetFlags)
	case "self-test", "selftest":
		fmt.Fprintln(os.Stderr, "Usage:\n  svgsteg self-test [--self-test-runs N] [--in optional-real.svg]")
		printFlagGroup("Self-test", addSelfTestFlags)
		printFlagGroup("Security mode", addSecurityModeFlags)
		printFlagGroup("Compression", addCompressionFlags)
		printFlagGroup("Carrier policy", addCarrierPolicyFlags)
		printFlagGroup("Capacity expansion / fallback", addExpansionFlags)
	default:
		usage("")
	}
}

func validateOpt(opt options) error {
	if opt.visiblePrecision < 0 || opt.visiblePrecision > 9 {
		return errors.New("--visible-precision must be between 0 and 9")
	}
	if opt.minExistingDecimals < 0 || opt.minExistingDecimals > 9 {
		return errors.New("--min-existing-decimals must be between 0 and 9")
	}
	if opt.kdfIterations < 1000 {
		return errors.New("--kdf-iterations must be >= 1000")
	}
	if opt.integerEpsilon < 0 || opt.simpleFractionEpsilon < 0 {
		return errors.New("epsilon values must be >= 0")
	}
	if !validEpsilonMode(opt.integerEpsilonMode) {
		return fmt.Errorf("invalid --integer-epsilon-mode %q", opt.integerEpsilonMode)
	}
	if !validEpsilonMode(opt.simpleFractionEpsilonMode) {
		return fmt.Errorf("invalid --simple-fraction-epsilon-mode %q", opt.simpleFractionEpsilonMode)
	}
	if opt.mapWidth < 8 || opt.mapWidth > 240 {
		return errors.New("--map-width must be between 8 and 240")
	}
	switch strings.ToLower(opt.mapMode) {
	case "dominant", "skipped", "eligible", "multi":
	default:
		return fmt.Errorf("invalid --map-mode %q", opt.mapMode)
	}
	if opt.targetBytes < 0 {
		return errors.New("--target-bytes must be >= 0")
	}
	if opt.diffMaxCanvas < 16 || opt.diffMaxCanvas > 4096 {
		return errors.New("--max-canvas must be between 16 and 4096")
	}
	if opt.diffAmplify < 1 || opt.diffAmplify > 255 {
		return errors.New("--diff-amplify must be between 1 and 255")
	}
	if _, err := parseDenominators(opt.fractionDenominators); err != nil {
		return err
	}
	if !validCompressionMode(opt.compression) {
		return fmt.Errorf("invalid --compression %q", opt.compression)
	}
	if opt.noEncrypt && (opt.passphrase != "" || opt.passphraseFile != "") {
		return errors.New("--no-encrypt cannot be combined with --passphrase or --passphrase-file")
	}
	return nil
}

func policyFrom(opt options, svg string) carrierPolicy {
	denoms, _ := parseDenominators(opt.fractionDenominators)
	vb := parseViewBox(svg)
	return carrierPolicy{
		VisiblePrecision:          opt.visiblePrecision,
		MinExistingDecimals:       opt.minExistingDecimals,
		SkipIntegerLike:           opt.skipIntegerLike,
		SkipSimpleFractions:       opt.skipSimpleFractions,
		IntegerEpsilon:            resolveEpsilon(opt.integerEpsilon, opt.integerEpsilonMode, vb),
		SimpleFractionEpsilon:     resolveEpsilon(opt.simpleFractionEpsilon, opt.simpleFractionEpsilonMode, vb),
		IntegerEpsilonRaw:         opt.integerEpsilon,
		SimpleFractionEpsilonRaw:  opt.simpleFractionEpsilon,
		IntegerEpsilonMode:        normalizeEpsilonMode(opt.integerEpsilonMode),
		SimpleFractionEpsilonMode: normalizeEpsilonMode(opt.simpleFractionEpsilonMode),
		SimpleFractionDenoms:      denoms,
		AllowDecimalizeIntegers:   opt.allowDecimalizeIntegers,
		InvisibleCarrierStyle:     opt.invisibleCarrierStyle,
		ViewBox:                   vb,
	}
}

func normalizeEpsilonMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	m = strings.ReplaceAll(m, "_", "-")
	switch m {
	case "", "abs", "absolute":
		return "absolute"
	case "width", "rel-width", "relative-width":
		return "relative-width"
	case "height", "rel-height", "relative-height":
		return "relative-height"
	case "diag", "diagonal", "rel-diagonal", "relative-diagonal":
		return "relative-diagonal"
	case "max", "rel-max", "relative-max", "relative-maximum":
		return "relative-max"
	default:
		return m
	}
}

func validEpsilonMode(mode string) bool {
	switch normalizeEpsilonMode(mode) {
	case "absolute", "relative-width", "relative-height", "relative-diagonal", "relative-max":
		return true
	default:
		return false
	}
}

func parseViewBox(svg string) viewBoxInfo {
	if m := viewBoxRe.FindStringSubmatch(svg); m != nil {
		parts := strings.Fields(strings.ReplaceAll(m[1], ",", " "))
		if len(parts) >= 4 {
			vals := make([]float64, 4)
			ok := true
			for i := range 4 {
				v, err := strconv.ParseFloat(parts[i], 64)
				if err != nil {
					ok = false
					break
				}
				vals[i] = v
			}
			if ok && vals[2] != 0 && vals[3] != 0 {
				if vals[2] < 0 {
					vals[2] = -vals[2]
				}
				if vals[3] < 0 {
					vals[3] = -vals[3]
				}
				return viewBoxInfo{Found: true, MinX: vals[0], MinY: vals[1], Width: vals[2], Height: vals[3]}
			}
		}
	}
	// Fallback: width/height attributes if they are plain numeric values.
	var w, h float64
	if m := widthRe.FindStringSubmatch(svg); m != nil {
		w, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := heightRe.FindStringSubmatch(svg); m != nil {
		h, _ = strconv.ParseFloat(m[1], 64)
	}
	if w > 0 && h > 0 {
		return viewBoxInfo{Found: true, Width: w, Height: h}
	}
	return viewBoxInfo{}
}

func resolveEpsilon(raw float64, mode string, vb viewBoxInfo) float64 {
	if raw <= 0 {
		return 0
	}
	switch normalizeEpsilonMode(mode) {
	case "absolute":
		return raw
	case "relative-width":
		if vb.Width > 0 {
			return raw * vb.Width
		}
	case "relative-height":
		if vb.Height > 0 {
			return raw * vb.Height
		}
	case "relative-diagonal":
		if vb.Width > 0 || vb.Height > 0 {
			return raw * math.Hypot(vb.Width, vb.Height)
		}
	case "relative-max":
		if vb.Width > 0 || vb.Height > 0 {
			return raw * math.Max(vb.Width, vb.Height)
		}
	}
	// If no viewBox/size exists, fall back to absolute so the tool remains usable.
	return raw
}

func viewBoxSummary(vb viewBoxInfo) string {
	if !vb.Found {
		return "not found; relative epsilon modes fall back to absolute"
	}
	return fmt.Sprintf("min=(%g,%g) size=(%g,%g) diag=%g", vb.MinX, vb.MinY, vb.Width, vb.Height, math.Hypot(vb.Width, vb.Height))
}

func usage(msg string) {
	if msg != "" {
		fmt.Fprintln(os.Stderr, "error:", msg)
	}
	fmt.Fprintln(os.Stderr, `
svgsteg - SVG path-coordinate binary steganography prototype

Usage:
  svgsteg <command> [options]

Commands:
  encode      Embed a payload into an SVG
  decode      Recover a payload from an SVG
  capacity    Analyze carrier capacity and numeric style
  diff        Render and compare two SVGs
  self-test   Run internal verification tests
  help        Show top-level or command-specific help

Examples:
  svgsteg encode --in logo.svg --payload secret.bin --out logo.steg.svg --passphrase-file pass.txt
  svgsteg encode --in logo.svg --payload-text "hello" --out logo.steg.svg --no-encrypt
  svgsteg decode --in logo.steg.svg --out recovered.bin --passphrase-file pass.txt
  svgsteg capacity --in logo.svg --histogram --map
  svgsteg diff --a logo.svg --b logo.steg.svg --renderer builtin-oksvg --diff-out diff.png

Run:
  svgsteg <command> --help
  svgsteg help <command>`)
	os.Exit(2)
}

func cmdEncode(args []string) error {
	var opt options
	fs := baseFlagSet("encode", &opt)
	_ = fs.Parse(args)
	if err := validateOpt(opt); err != nil {
		return err
	}
	if opt.inPath == "" || opt.outPath == "" {
		return errors.New("encode requires --in and --out")
	}
	if opt.allowInvisibleCarrier {
		opt.smartAllowInvisible = true
	}
	if opt.inPath == "-" && opt.payloadPath == "-" {
		return errors.New("encode cannot read both --in - and --payload - from stdin")
	}
	logw := commandLogWriter(opt.outPath)
	if opt.outPath == "-" && opt.verbose {
		fmt.Fprintln(os.Stderr, "warning: --out - sends binary/SVG output to stdout; verbose smart trace is suppressed")
		opt.verbose = false
	}
	pass, err := readPassphrase(opt)
	if err != nil {
		return err
	}
	svg, err := readPathOrStdin(opt.inPath)
	if err != nil {
		return err
	}
	payload, payloadLabel, err := readPayloadBytes(opt)
	if err != nil {
		return err
	}
	if opt.verbose {
		printInputAccounting(logw, opt, len(svg), payload, payloadLabel)
	}
	var encoded []byte
	var stats EncodeStats
	var smart SmartResult
	if opt.smart {
		encoded, stats, smart, err = SmartEncodeSVG(svg, payload, pass, opt)
	} else {
		encoded, stats, err = EncodeSVG(svg, payload, pass, opt)
	}
	if err != nil {
		return err
	}
	if !opt.noVerifyRoundtrip {
		if err := verifyEncodeRoundtrip(encoded, payload, pass, opt, smart); err != nil {
			return fmt.Errorf("encode round-trip self-check FAILED (output NOT written): %w", err)
		}
	}
	if err := writePathOrStdout(opt.outPath, encoded, 0644); err != nil {
		return err
	}
	fmt.Fprintf(logw, "input SVG size:        %d bytes\n", len(svg))
	fmt.Fprintf(logw, "output SVG size:       %d bytes\n", len(encoded))
	fmt.Fprintf(logw, "SVG size delta:        %+d bytes (%.2f%%)\n", len(encoded)-len(svg), 100*float64(len(encoded)-len(svg))/float64(maxInt(1, len(svg))))
	fmt.Fprintf(logw, "encoded payload:       %d bytes\n", len(payload))
	if opt.noEncrypt {
		fmt.Fprintf(logw, "security mode:         no-encrypt (integrity only; no secrecy)\n")
	}
	fmt.Fprintf(logw, "compression:           %s (%d -> %d bytes)\n", stats.CompressionMode, stats.PayloadBytes, stats.CompressedBytes)
	fmt.Fprintf(logw, "carrier stream:        %d bytes\n", stats.StreamBytes)
	fmt.Fprintf(logw, "natural carriers:      %d\n", stats.NaturalCarriers)
	fmt.Fprintf(logw, "subdivision carriers:  %d\n", stats.SubdivisionCarriers)
	fmt.Fprintf(logw, "invisible carriers:    %d\n", stats.InvisibleCarriers)
	if opt.smart {
		fmt.Fprintf(logw, "smart profile:         %s\n", smart.ProfileName)
		fmt.Fprintf(logw, "visual check:          %s\n", smart.VisualSummary())
		fmt.Fprintf(logw, "decode with:           %s\n", decodeCommand(opt.outPath, opt.passphraseFile, smart.SelectedOpt))
	}
	fmt.Fprintf(logw, "output:                %s\n", opt.outPath)
	if err := emitEncodeSidecars(svg, encoded, opt, logw); err != nil {
		fmt.Fprintf(logw, "sidecar warning:       %v\n", err)
	}
	return nil
}

// verifyEncodeRoundtrip decodes the freshly-encoded SVG in-memory using the
// carrier policy actually used to encode, and asserts it recovers the exact
// original payload. It runs BEFORE the output is written, so an unrecoverable
// encode fails loudly (non-zero exit) instead of producing a silently-broken
// artifact. This is payload-recoverability — distinct from the visual render-diff
// performed by --visual-check.
func verifyEncodeRoundtrip(encoded, payload, pass []byte, opt options, smart SmartResult) error {
	verifyOpt := opt
	if opt.smart {
		verifyOpt = smart.SelectedOpt
	}
	pol := policyFrom(verifyOpt, string(encoded))
	recovered, _, err := decodeSVGAutoMode(encoded, pass, pol, opt.noEncrypt, pass == nil)
	if err != nil {
		return fmt.Errorf("re-decode of encoded output failed: %w", err)
	}
	if !bytes.Equal(recovered, payload) {
		return fmt.Errorf("recovered payload mismatch: got %d bytes, want %d", len(recovered), len(payload))
	}
	return nil
}

func cmdDecode(args []string) error {
	var opt options
	fs := baseFlagSet("decode", &opt)
	_ = fs.Parse(args)
	if err := validateOpt(opt); err != nil {
		return err
	}
	if opt.inPath == "" || opt.outPath == "" {
		return errors.New("decode requires --in and --out")
	}
	logw := commandLogWriter(opt.outPath)
	pass, err := readOptionalPassphrase(opt)
	if err != nil {
		return err
	}
	svg, err := readPathOrStdin(opt.inPath)
	if err != nil {
		return err
	}
	pol := policyFrom(opt, string(svg))
	payload, usedNoEncrypt, err := decodeSVGAutoMode(svg, pass, pol, opt.noEncrypt, pass == nil)
	if err != nil {
		return err
	}
	if opt.outPath == "-" {
		// Keep diagnostics away from the payload stream and emit them before stdout.
		fmt.Fprintf(logw, "decoded payload: %d bytes\n", len(payload))
		if usedNoEncrypt && !opt.noEncrypt {
			fmt.Fprintf(logw, "security mode:   auto-detected no-encrypt (integrity only; no secrecy)\n")
		}
		fmt.Fprintf(logw, "output:          %s\n", opt.outPath)
	}
	if err := writePathOrStdout(opt.outPath, payload, 0644); err != nil {
		return err
	}
	if opt.outPath != "-" {
		fmt.Fprintf(logw, "decoded payload: %d bytes\n", len(payload))
		if usedNoEncrypt && !opt.noEncrypt {
			fmt.Fprintf(logw, "security mode:   auto-detected no-encrypt (integrity only; no secrecy)\n")
		}
		fmt.Fprintf(logw, "output:          %s\n", opt.outPath)
	}
	return nil
}

func decodeSVGAutoMode(svg []byte, pass []byte, pol carrierPolicy, requestedNoEncrypt bool, noPassphrase bool) ([]byte, bool, error) {
	if requestedNoEncrypt {
		payload, err := DecodeSVGWithMode(svg, pass, pol, true)
		return payload, true, err
	}

	if noPassphrase {
		if payload, err := DecodeSVGWithMode(svg, nil, pol, true); err == nil {
			return payload, true, nil
		}
		return nil, false, errors.New("no payload decoded without a passphrase; if this SVG is encrypted, provide --passphrase-file or --passphrase; if it is integrity-only, retry with matching carrier-policy flags or --no-encrypt")
	}

	payload, err := DecodeSVGWithMode(svg, pass, pol, false)
	if err == nil {
		return payload, false, nil
	}
	if publicPayload, publicErr := DecodeSVGWithMode(svg, nil, pol, true); publicErr == nil {
		return publicPayload, true, nil
	}
	return nil, false, err
}

type suggestionRow struct {
	Name     string
	Opt      options
	Capacity int
	Skips    CarrierAnalysis
	Score    int
	Note     string
}

func estimateTargetCarrierBytes(opt options) (int, string, error) {
	if opt.payloadPath != "" || opt.payloadText != "" {
		payload, label, err := readPayloadBytes(opt)
		if err != nil {
			return 0, "", err
		}
		_, comp, err := chooseCompression(payload, opt.compression)
		if err != nil {
			return 0, "", err
		}
		stream := estimateCarrierStreamBytes(comp.Size, opt.noEncrypt)
		mode := "encrypted"
		if opt.noEncrypt {
			mode = "no-encrypt"
		}
		return stream, fmt.Sprintf("estimated %s stream for payload %s using %s: %d carrier bytes", mode, label, comp.Name, stream), nil
	}
	if opt.targetBytes > 0 {
		return opt.targetBytes, fmt.Sprintf("target bytes: %d", opt.targetBytes), nil
	}
	return 0, "no target supplied; showing capacity profiles only", nil
}

func estimateCarrierStreamBytes(compressedLen int, noEncrypt bool) int {
	// Inner/plain frame: magic(8)+compID(1)+origLen(8)+sha256(32)+compLen(8)+compressed.
	inner := 8 + 1 + 8 + 32 + 8 + compressedLen
	if noEncrypt {
		return inner
	}
	// Outer encrypted frame: magic(8)+iters(4)+salt(16)+nonce(12)+ctLen(8)+ciphertext+GCM tag(16).
	return 8 + 4 + 16 + 12 + 8 + inner + 16
}

func printCapacitySuggestions(svg string, base options) error {
	target, targetMsg, err := estimateTargetCarrierBytes(base)
	if err != nil {
		return err
	}
	fmt.Println("capacity suggestion sweep")
	fmt.Printf("  %s\n", targetMsg)
	rows := []suggestionRow{}
	add := func(name string, o options, score int, note string) {
		pol := policyFrom(o, svg)
		a := analyzeCarriers(svg, pol)
		cap := a.Eligible
		rows = append(rows, suggestionRow{Name: name, Opt: o, Capacity: cap, Skips: a, Score: score, Note: note})
		// Also estimate true subdivision if the profile needs help or if no target was supplied.
		if target == 0 || cap < target {
			oSub := o
			oSub.subdivide = true
			subTarget := target
			if subTarget <= 0 {
				subTarget = cap + 1024
			}
			if expanded, added, err := subdivideSVGForCapacity(svg, subTarget, pol); err == nil && added > 0 {
				capSub := countEligiblePathNumbers(expanded, pol)
				rows = append(rows, suggestionRow{Name: name + " + subdivide", Opt: oSub, Capacity: capSub, Skips: a, Score: score + 18, Note: fmt.Sprintf("adds ~%d path carriers", added)})
			}
		}
		if target > 0 && cap < target {
			oInv := o
			oInv.allowInvisibleCarrier = true
			rows = append(rows, suggestionRow{Name: name + " + invisible fallback", Opt: oInv, Capacity: target, Skips: a, Score: score + 45, Note: "meets target by synthetic invisible carrier"})
		}
	}
	// Lower score is less suspicious / stricter.
	for _, md := range []int{3, 2, 1, 0} {
		o := base
		o.minExistingDecimals = md
		o.skipIntegerLike = true
		o.skipSimpleFractions = true
		o.allowDecimalizeIntegers = false
		add(fmt.Sprintf("min-decimals=%d strict skips", md), o, (3-md)*10, "natural only")
		o2 := o
		o2.skipSimpleFractions = false
		add(fmt.Sprintf("min-decimals=%d allow simple fractions", md), o2, (3-md)*10+12, "uses grid-ish fractions")
		o3 := o2
		o3.skipIntegerLike = false
		add(fmt.Sprintf("min-decimals=%d allow integers/fractions", md), o3, (3-md)*10+25, "uses integer/fraction-like decimals")
		if md == 0 {
			o4 := o3
			o4.allowDecimalizeIntegers = true
			add("min-decimals=0 decimalize integers", o4, 60, "may create 4.000XYZ-style values")
		}
	}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && (rows[j].Score < rows[j-1].Score || (rows[j].Score == rows[j-1].Score && rows[j].Capacity > rows[j-1].Capacity)); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	fmt.Printf("  %-58s %9s %7s %-32s %s\n", "profile", "capacity", "score", "note", "suggested flags")
	shown := 0
	for _, r := range rows {
		ok := target == 0 || r.Capacity >= target
		if target > 0 && !ok && shown >= 10 {
			continue
		}
		mark := " "
		if ok && target > 0 {
			mark = "*"
		}
		fmt.Printf("%s %-58s %9d %7d %-32s %s\n", mark, r.Name, r.Capacity, r.Score, r.Note, suggestionFlags(r.Opt, base))
		shown++
		if target > 0 && ok && shown >= 10 {
			break
		}
		if target == 0 && shown >= 16 {
			break
		}
	}
	if target > 0 {
		fmt.Println("  * profiles that meet or exceed the target")
	}
	return nil
}

func suggestionFlags(o, base options) string {
	parts := []string{}
	if o.minExistingDecimals != base.minExistingDecimals {
		parts = append(parts, fmt.Sprintf("--min-existing-decimals %d", o.minExistingDecimals))
	}
	if !o.skipSimpleFractions {
		parts = append(parts, "--skip-simple-fractions=false")
	}
	if !o.skipIntegerLike {
		parts = append(parts, "--skip-integer-like=false")
	}
	if o.allowDecimalizeIntegers {
		parts = append(parts, "--allow-decimalize-integers")
	}
	if o.subdivide && !base.subdivide {
		parts = append(parts, "--subdivide")
	}
	if o.allowInvisibleCarrier && !base.allowInvisibleCarrier {
		parts = append(parts, "--allow-invisible-carrier")
	}
	if len(parts) == 0 {
		return "(current/default profile)"
	}
	return strings.Join(parts, " ")
}

func cmdCapacity(args []string) error {
	var opt options
	fs := baseFlagSet("capacity", &opt)
	_ = fs.Parse(args)
	if err := validateOpt(opt); err != nil {
		return err
	}
	if opt.inPath == "" {
		return errors.New("capacity requires --in")
	}
	svg, err := os.ReadFile(opt.inPath)
	if err != nil {
		return err
	}
	pol := policyFrom(opt, string(svg))
	analysis := printCarrierBreakdown(string(svg), pol)
	fmt.Printf("visible precision:         %d decimals\n", opt.visiblePrecision)
	fmt.Printf("min existing decimals:     %d\n", opt.minExistingDecimals)
	fmt.Printf("viewBox/size:              %s\n", viewBoxSummary(pol.ViewBox))
	fmt.Printf("skip integer-like:         %v epsilon=%g mode=%s effective=%g\n", opt.skipIntegerLike, opt.integerEpsilon, pol.IntegerEpsilonMode, pol.IntegerEpsilon)
	fmt.Printf("skip simple fractions:     %v epsilon=%g mode=%s effective=%g denominators=%s\n", opt.skipSimpleFractions, opt.simpleFractionEpsilon, pol.SimpleFractionEpsilonMode, pol.SimpleFractionEpsilon, opt.fractionDenominators)
	fmt.Printf("allow decimalized ints:    %v\n", opt.allowDecimalizeIntegers)
	if opt.showMap {
		printCarrierMap(string(svg), analysis, opt.mapWidth, opt.mapMode)
	}
	if opt.showHistogram {
		printNumericHistograms(string(svg), opt.histWidth)
	}
	if opt.suggest {
		if err := printCapacitySuggestions(string(svg), opt); err != nil {
			return err
		}
	}
	if opt.subdivide {
		expanded, added, err := subdivideSVGForCapacity(string(svg), 1000000, pol)
		if err == nil {
			fmt.Printf("subdivision added approx:  %d carriers\n", added)
			fmt.Printf("post-subdivision capacity: %d bytes\n", countEligiblePathNumbers(expanded, pol))
		} else {
			fmt.Printf("subdivision estimate err:  %v\n", err)
		}
	}
	return nil
}

func renderDims(svgA, svgB string, maxCanvas int) (int, int) {
	vb := parseViewBox(svgA)
	if !vb.Found || vb.Width <= 0 || vb.Height <= 0 {
		vb = parseViewBox(svgB)
	}
	if !vb.Found || vb.Width <= 0 || vb.Height <= 0 {
		return maxCanvas, maxCanvas
	}
	scale := float64(maxCanvas) / math.Max(vb.Width, vb.Height)
	w := int(math.Round(vb.Width * scale))
	h := int(math.Round(vb.Height * scale))
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	return w, h
}

type DiffStats struct {
	Renderer   string
	Width      int
	Height     int
	Changed    int
	Total      int
	ChangedPct float64
	MaxDelta   uint8
	MeanDelta  float64
}

func checkVisualBudget(d DiffStats, opt options) error {
	if opt.maxChangedPixelsPct > 0 && d.ChangedPct > opt.maxChangedPixelsPct {
		return fmt.Errorf("changed pixels %.6f%% > %.6f%%", d.ChangedPct, opt.maxChangedPixelsPct)
	}
	if opt.maxMeanChannelDelta > 0 && d.MeanDelta > opt.maxMeanChannelDelta {
		return fmt.Errorf("mean channel delta %.6f > %.6f", d.MeanDelta, opt.maxMeanChannelDelta)
	}
	if opt.maxChannelDelta > 0 && int(d.MaxDelta) > opt.maxChannelDelta {
		return fmt.Errorf("max channel delta %d > %d", d.MaxDelta, opt.maxChannelDelta)
	}
	return nil
}

func copyFile(srcPath, dstPath string) error {
	b, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	return os.WriteFile(dstPath, b, 0644)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func abs8(a, b uint8) uint8 {
	if a > b {
		return a - b
	}
	return b - a
}
func max4(a, b, c, d uint8) uint8 {
	return max(a, b, c, d)
}
func satMul(v uint8, n int) uint8 {
	x := int(v) * n
	if x > 255 {
		return 255
	}
	return uint8(x)
}

func cmdSelfTest(args []string) error {
	var opt options
	fs := baseFlagSet("self-test", &opt)
	_ = fs.Parse(args)
	if err := validateOpt(opt); err != nil {
		return err
	}
	if opt.selfTestRuns < 1 {
		opt.selfTestRuns = 1
	}
	// Exercise the new capacity invention path by default.
	opt.subdivide = true
	opt.allowInvisibleCarrier = true
	opt.kdfIterations = 2000
	return runSelfTest(opt)
}

func commandLogWriter(outPath string) io.Writer {
	if outPath == "-" {
		return os.Stderr
	}
	return os.Stdout
}

func readPathOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writePathOrStdout(path string, data []byte, perm os.FileMode) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, perm)
}

func readPayloadBytes(opt options) ([]byte, string, error) {
	sources := 0
	if opt.payloadPath != "" {
		sources++
	}
	if opt.payloadText != "" {
		sources++
	}
	if sources != 1 {
		return nil, "", errors.New("encode requires exactly one payload source: --payload FILE, --payload -, or --payload-text TEXT")
	}
	if opt.payloadText != "" {
		return []byte(opt.payloadText), "--payload-text", nil
	}
	if opt.payloadPath == "-" {
		b, err := io.ReadAll(os.Stdin)
		return b, "stdin", err
	}
	b, err := os.ReadFile(opt.payloadPath)
	return b, opt.payloadPath, err
}

func printInputAccounting(w io.Writer, opt options, svgBytes int, payload []byte, payloadLabel string) {
	fmt.Fprintf(w, "input SVG size:        %d bytes\n", svgBytes)
	fmt.Fprintf(w, "payload source:        %s\n", payloadLabel)
	fmt.Fprintf(w, "payload size:          %d bytes\n", len(payload))
	if compressed, comp, err := chooseCompression(payload, opt.compression); err == nil {
		fmt.Fprintf(w, "compression estimate:  %s (%d -> %d bytes)\n", comp.Name, len(payload), len(compressed))
		fmt.Fprintf(w, "carrier estimate:      %d bytes required\n", estimateCarrierStreamBytes(len(compressed), opt.noEncrypt))
	}
	if opt.noEncrypt {
		fmt.Fprintf(w, "security mode:         no-encrypt (integrity only; no secrecy)\n")
	}
}

func readPassphrase(opt options) ([]byte, error) {
	if opt.noEncrypt {
		return nil, nil
	}
	if opt.passphraseFile != "" {
		b, err := os.ReadFile(opt.passphraseFile)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(b, "\r\n"), nil
	}
	if opt.passphrase != "" {
		return []byte(opt.passphrase), nil
	}
	return nil, errors.New("passphrase required: use --passphrase-file or --passphrase, or opt into integrity-only mode with --no-encrypt")
}

func readOptionalPassphrase(opt options) ([]byte, error) {
	if opt.noEncrypt {
		return nil, nil
	}
	if opt.passphraseFile != "" {
		b, err := os.ReadFile(opt.passphraseFile)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(b, "\r\n"), nil
	}
	if opt.passphrase != "" {
		return []byte(opt.passphrase), nil
	}
	return nil, nil
}

type SmartResult struct {
	ProfileName string
	SelectedOpt options
	Diff        *DiffStats
	VisualErr   error
}

func (r SmartResult) VisualSummary() string {
	if r.Diff == nil {
		if r.VisualErr != nil {
			return "skipped/failed: " + r.VisualErr.Error()
		}
		return "disabled"
	}
	return fmt.Sprintf("pass renderer=%s canvas=%dx%d changed=%.6f%% max=%d mean=%.6f", r.Diff.Renderer, r.Diff.Width, r.Diff.Height, r.Diff.ChangedPct, r.Diff.MaxDelta, r.Diff.MeanDelta)
}

type smartProfile struct {
	Name string
	Opt  options
}

func SmartEncodeSVG(svg []byte, payload []byte, passphrase []byte, base options) ([]byte, EncodeStats, SmartResult, error) {
	profiles := smartProfiles(base)
	var failures []string
	if base.visualCheck && !rendererBuiltIn {
		fmt.Println("smart: visual-fidelity check disabled — renderer not built in (-tags norender); selecting by round-trip verify + capacity only")
	}
	for _, prof := range profiles {
		candidate, stats, err := EncodeSVG(svg, payload, passphrase, prof.Opt)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: encode: %v", prof.Name, err))
			continue
		}
		decoded, err := DecodeSVGWithMode(candidate, passphrase, policyFrom(prof.Opt, string(candidate)), prof.Opt.noEncrypt)
		if err != nil || !bytes.Equal(decoded, payload) {
			if err == nil {
				err = errors.New("decoded payload mismatch")
			}
			failures = append(failures, fmt.Sprintf("%s: decode verify: %v", prof.Name, err))
			continue
		}
		var ds *DiffStats
		if base.visualCheck && rendererBuiltIn {
			d, err := diffSVGBytes(svg, candidate, base.visualRenderer, base.visualMaxCanvas, base.diffAmplify)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: visual check: %v", prof.Name, err))
				continue
			}
			ds = &d
			if err := checkVisualBudget(d, base); err != nil {
				failures = append(failures, fmt.Sprintf("%s: visual budget: %v", prof.Name, err))
				continue
			}
		}
		if base.verbose {
			fmt.Printf("smart accepted profile: %s\n", prof.Name)
			for _, f := range failures {
				fmt.Printf("  rejected: %s\n", f)
			}
		}
		return candidate, stats, SmartResult{ProfileName: prof.Name, SelectedOpt: prof.Opt, Diff: ds}, nil
	}
	if !base.smartAllowInvisible {
		failures = append(failures, "invisible-fallback: skipped because --allow-invisible-carrier/--smart-allow-invisible was not set")
	}
	return nil, EncodeStats{}, SmartResult{}, fmt.Errorf("smart encode found no acceptable profile:\n  %s", strings.Join(failures, "\n  "))
}

func smartProfiles(base options) []smartProfile {
	mk := func(name string, minDec int, skipInt, skipFrac, decInt, subdiv, invis bool) smartProfile {
		o := base
		o.smart = false
		o.minExistingDecimals = minDec
		o.skipIntegerLike = skipInt
		o.skipSimpleFractions = skipFrac
		o.allowDecimalizeIntegers = decInt
		o.subdivide = subdiv
		o.allowInvisibleCarrier = invis
		return smartProfile{Name: name, Opt: o}
	}
	profiles := []smartProfile{
		mk("strict-natural", 3, true, true, false, false, false),
		mk("natural-min2", 2, true, true, false, false, false),
		mk("natural-min1", 1, true, true, false, false, false),
		mk("lax-fractions-min2", 2, true, false, false, false, false),
		mk("decimalize-integers", 0, false, false, true, false, false),
		mk("subdivide-min2", 2, true, true, false, true, false),
		mk("subdivide-min1", 1, true, true, false, true, false),
	}
	if base.smartAllowInvisible {
		profiles = append(profiles, mk("invisible-fallback", 2, true, true, false, true, true))
	}
	return profiles
}

func decodeCommand(inPath, passFile string, opt options) string {
	parts := []string{"svgsteg", "decode", "--in", inPath, "--out", "recovered.bin"}
	if opt.noEncrypt {
		parts = append(parts, "--no-encrypt")
	} else if passFile != "" {
		parts = append(parts, "--passphrase-file", passFile)
	} else {
		parts = append(parts, "--passphrase", "<passphrase>")
	}
	parts = append(parts, "--min-existing-decimals", strconv.Itoa(opt.minExistingDecimals))
	if !opt.skipIntegerLike {
		parts = append(parts, "--skip-integer-like=false")
	}
	if !opt.skipSimpleFractions {
		parts = append(parts, "--skip-simple-fractions=false")
	}
	if opt.allowDecimalizeIntegers {
		parts = append(parts, "--allow-decimalize-integers")
	}
	if opt.visiblePrecision != defaultVisiblePrecision {
		parts = append(parts, "--visible-precision", strconv.Itoa(opt.visiblePrecision))
	}
	return strings.Join(parts, " ")
}

type EncodeStats struct {
	StreamBytes, NaturalCarriers, SubdivisionCarriers, InvisibleCarriers int
	PayloadBytes, CompressedBytes                                        int
	CompressionMode                                                      string
}

func EncodeSVG(svg []byte, payload []byte, passphrase []byte, opt options) ([]byte, EncodeStats, error) {
	pol := policyFrom(opt, string(svg))
	stream, compStats, err := buildCarrierStream(payload, passphrase, pol, opt)
	if err != nil {
		return nil, EncodeStats{}, err
	}
	work := string(svg)
	natural := countEligiblePathNumbers(work, pol)
	subAdded := 0
	if natural < len(stream) && opt.subdivide {
		var err error
		work, subAdded, err = subdivideSVGForCapacity(work, len(stream), pol)
		if err != nil {
			return nil, EncodeStats{}, err
		}
	}
	capacity := countEligiblePathNumbers(work, pol)
	invis := 0
	if capacity < len(stream) {
		if !opt.allowInvisibleCarrier {
			return nil, EncodeStats{}, fmt.Errorf("insufficient capacity: need %d eligible carriers, have %d; retry with --subdivide or --allow-invisible-carrier", len(stream), capacity)
		}
		invis = len(stream) - capacity
		work, err = injectCarrierPath(work, invis, pol)
		if err != nil {
			return nil, EncodeStats{}, err
		}
	}
	out, used, err := encodeStreamIntoSVG(work, stream, pol)
	if err != nil {
		return nil, EncodeStats{}, err
	}
	if used != len(stream) {
		return nil, EncodeStats{}, fmt.Errorf("internal error: encoded %d/%d bytes", used, len(stream))
	}
	return []byte(out), EncodeStats{
		StreamBytes:         len(stream),
		NaturalCarriers:     natural,
		SubdivisionCarriers: subAdded,
		InvisibleCarriers:   invis,
		PayloadBytes:        len(payload),
		CompressedBytes:     compStats.Size,
		CompressionMode:     compStats.Name,
	}, nil
}

func DecodeSVG(svg []byte, passphrase []byte, pol carrierPolicy) ([]byte, error) {
	return DecodeSVGWithMode(svg, passphrase, pol, false)
}

func DecodeSVGWithMode(svg []byte, passphrase []byte, pol carrierPolicy, noEncrypt bool) ([]byte, error) {
	stream := extractCarrierBytes(string(svg), pol)
	if len(stream) < 8 {
		return nil, errors.New("no carrier stream found")
	}
	return parseCarrierStream(stream, passphrase, pol, noEncrypt)
}

func buildCarrierStream(payload, passphrase []byte, pol carrierPolicy, opt options) ([]byte, compressionStats, error) {
	if opt.noEncrypt {
		return buildPublicStream(payload, opt.compression)
	}
	return buildEncryptedStream(payload, passphrase, pol, opt.kdfIterations, opt.compression)
}

func buildPublicStream(payload []byte, compressionMode string) ([]byte, compressionStats, error) {
	compressed, compStats, err := chooseCompression(payload, compressionMode)
	if err != nil {
		return nil, compressionStats{}, err
	}
	sum := sha256.Sum256(payload)
	out := new(bytes.Buffer)
	out.WriteString(publicMagic)
	out.WriteByte(compStats.ID)
	binary.Write(out, binary.BigEndian, uint64(len(payload)))
	out.Write(sum[:])
	binary.Write(out, binary.BigEndian, uint64(len(compressed)))
	out.Write(compressed)
	return out.Bytes(), compStats, nil
}

func buildEncryptedStream(payload, passphrase []byte, pol carrierPolicy, iterations int, compressionMode string) ([]byte, compressionStats, error) {
	compressed, compStats, err := chooseCompression(payload, compressionMode)
	if err != nil {
		return nil, compressionStats{}, err
	}
	sum := sha256.Sum256(payload)
	plain := new(bytes.Buffer)
	plain.WriteString(innerMagic)
	plain.WriteByte(compStats.ID)
	binary.Write(plain, binary.BigEndian, uint64(len(payload)))
	plain.Write(sum[:])
	binary.Write(plain, binary.BigEndian, uint64(len(compressed)))
	plain.Write(compressed)
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, compressionStats{}, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, compressionStats{}, err
	}
	key := pbkdf2SHA256(passphrase, salt, iterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, compressionStats{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, compressionStats{}, err
	}
	aad := aadFor(pol)
	ct := gcm.Seal(nil, nonce, plain.Bytes(), aad)
	out := new(bytes.Buffer)
	out.WriteString(outerMagic)
	binary.Write(out, binary.BigEndian, uint32(iterations))
	out.Write(salt)
	out.Write(nonce)
	binary.Write(out, binary.BigEndian, uint64(len(ct)))
	out.Write(ct)
	return out.Bytes(), compStats, nil
}

func parseCarrierStream(stream, passphrase []byte, pol carrierPolicy, noEncrypt bool) ([]byte, error) {
	if noEncrypt {
		return parsePublicStream(stream)
	}
	return parseEncryptedStream(stream, passphrase, pol)
}

func parsePublicStream(stream []byte) ([]byte, error) {
	if len(stream) < 8+1+8+32+8 {
		return nil, errors.New("public carrier stream too short")
	}
	if string(stream[:8]) != publicMagic {
		return nil, errors.New("public magic marker not found; wrong SVG, wrong precision, or wrong carrier policy")
	}
	pos := 8
	compID := stream[pos]
	pos++
	origLen := binary.BigEndian.Uint64(stream[pos : pos+8])
	pos += 8
	expected := stream[pos : pos+32]
	pos += 32
	compLen := binary.BigEndian.Uint64(stream[pos : pos+8])
	pos += 8
	if compLen > uint64(len(stream)-pos) {
		return nil, errors.New("compressed length exceeds public frame")
	}
	payload, err := decompressByID(compID, stream[pos:pos+int(compLen)])
	if err != nil {
		return nil, err
	}
	if uint64(len(payload)) != origLen {
		return nil, fmt.Errorf("length mismatch: got %d expected %d", len(payload), origLen)
	}
	actual := sha256.Sum256(payload)
	if !hmac.Equal(actual[:], expected) {
		return nil, errors.New("payload SHA-256 mismatch")
	}
	return payload, nil
}

func parseEncryptedStream(stream, passphrase []byte, pol carrierPolicy) ([]byte, error) {
	if len(stream) < 8+4+16+12+8 {
		return nil, errors.New("carrier stream too short")
	}
	if string(stream[:8]) != outerMagic {
		return nil, errors.New("magic marker not found; wrong SVG, wrong precision, or wrong carrier policy")
	}
	pos := 8
	iter := int(binary.BigEndian.Uint32(stream[pos : pos+4]))
	pos += 4
	if iter < 1000 || iter > 10000000 {
		return nil, errors.New("invalid KDF iteration count")
	}
	salt := stream[pos : pos+16]
	pos += 16
	nonce := stream[pos : pos+12]
	pos += 12
	ctLen := binary.BigEndian.Uint64(stream[pos : pos+8])
	pos += 8
	if ctLen > uint64(len(stream)-pos) {
		return nil, errors.New("ciphertext length exceeds available carrier data")
	}
	ct := stream[pos : pos+int(ctLen)]
	key := pbkdf2SHA256(passphrase, salt, iter, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, aadFor(pol))
	if err != nil {
		return nil, errors.New("authentication failed; wrong passphrase, wrong carrier policy, or tampered SVG")
	}
	return parseInnerFrame(plain)
}

func aadFor(pol carrierPolicy) []byte {
	return fmt.Appendf(nil, "svgsteg-v3|visible=%d|min=%d|digits=%d|skipint=%v|inteps=%g|skipfrac=%v|fraceps=%g|denoms=%v|decint=%v", pol.VisiblePrecision, pol.MinExistingDecimals, carrierDigits, pol.SkipIntegerLike, pol.IntegerEpsilon, pol.SkipSimpleFractions, pol.SimpleFractionEpsilon, pol.SimpleFractionDenoms, pol.AllowDecimalizeIntegers)
}

func parseInnerFrame(plain []byte) ([]byte, error) {
	if len(plain) < 8+1+8+32+8 {
		return nil, errors.New("inner frame too short")
	}
	pos := 0
	if string(plain[pos:pos+8]) != innerMagic {
		return nil, errors.New("inner magic mismatch")
	}
	pos += 8
	compID := plain[pos]
	pos++
	origLen := binary.BigEndian.Uint64(plain[pos : pos+8])
	pos += 8
	expected := plain[pos : pos+32]
	pos += 32
	compLen := binary.BigEndian.Uint64(plain[pos : pos+8])
	pos += 8
	if compLen > uint64(len(plain)-pos) {
		return nil, errors.New("compressed length exceeds inner frame")
	}
	payload, err := decompressByID(compID, plain[pos:pos+int(compLen)])
	if err != nil {
		return nil, err
	}
	if uint64(len(payload)) != origLen {
		return nil, fmt.Errorf("length mismatch: got %d expected %d", len(payload), origLen)
	}
	actual := sha256.Sum256(payload)
	if !hmac.Equal(actual[:], expected) {
		return nil, errors.New("payload SHA-256 mismatch")
	}
	return payload, nil
}

// Compression lives in compression.go (registry + consumers) and the build-tagged
// codec files compression_stdlib.go / compression_brotli.go.

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2(password, salt, iter, keyLen, sha256.New)
}
func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	mac := hmac.New(h, password)
	hLen := mac.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	var bi [4]byte
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(bi[:], uint32(block))
		mac.Reset()
		mac.Write(salt)
		mac.Write(bi[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func pathDFromMatch(m []string) string {
	if len(m) > 4 && m[4] != "" {
		return m[4]
	}
	if len(m) > 6 {
		return m[6]
	}
	return ""
}

type CarrierAnalysis struct {
	TotalPathNumbers   int
	Eligible           int
	NoDecimal          int
	Scientific         int
	TooFewDecimals     int
	IntegerLike        int
	SimpleFractionLike int
	Malformed          int
	TokenOffsets       []TokenMark
}

type TokenMark struct {
	Offset int
	Kind   byte
}

const (
	kindNumeric  byte = 'd'
	kindTooFew   byte = 'o'
	kindGrid     byte = 't'
	kindEligible byte = 'e'
)

func analyzeCarriers(svg string, pol carrierPolicy) CarrierAnalysis {
	var a CarrierAnalysis
	matches := pathDRe.FindAllStringSubmatchIndex(svg, -1)
	for _, mi := range matches {
		if len(mi) < 14 {
			continue
		}
		dStart, dEnd := -1, -1
		if mi[8] >= 0 {
			dStart, dEnd = mi[8], mi[9]
		} else if mi[12] >= 0 {
			dStart, dEnd = mi[12], mi[13]
		}
		if dStart < 0 || dEnd < 0 {
			continue
		}
		d := svg[dStart:dEnd]
		for _, ni := range numberRe.FindAllStringIndex(d, -1) {
			tok := d[ni[0]:ni[1]]
			reason := carrierReason(tok, pol)
			a.TotalPathNumbers++
			mark := kindNumeric
			switch reason {
			case "eligible":
				a.Eligible++
				mark = kindEligible
			case "no-decimal":
				a.NoDecimal++
				mark = kindTooFew
			case "scientific":
				a.Scientific++
				mark = kindNumeric
			case "too-few-decimals":
				a.TooFewDecimals++
				mark = kindTooFew
			case "integer-like":
				a.IntegerLike++
				mark = kindGrid
			case "simple-fraction-like":
				a.SimpleFractionLike++
				mark = kindGrid
			default:
				a.Malformed++
				mark = kindNumeric
			}
			a.TokenOffsets = append(a.TokenOffsets, TokenMark{Offset: dStart + ni[0], Kind: mark})
		}
	}
	return a
}

func carrierReason(tok string, pol carrierPolicy) string {
	s := strings.TrimSpace(tok)
	if s == "" {
		return "malformed"
	}
	if strings.ContainsAny(s, "eE") {
		return "scientific"
	}
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	_, frac, hasDot := strings.Cut(s, ".")
	if !hasDot {
		if !pol.AllowDecimalizeIntegers || pol.MinExistingDecimals > 0 {
			return "no-decimal"
		}
		// Explicitly-gated aggressive mode: allow integer lexical tokens to become
		// decimal residual carriers. Other skip checks still apply, so callers
		// usually also need --skip-integer-like=false for values like 4.
		v, err := strconv.ParseFloat(tok, 64)
		if err != nil {
			return "malformed"
		}
		if v < 0 {
			v = -v
		}
		baseVal := roundTo(v, pol.VisiblePrecision)
		if pol.SkipIntegerLike && isNearInteger(baseVal, pol.IntegerEpsilon) {
			return "integer-like"
		}
		if pol.SkipSimpleFractions && isNearSimpleFraction(baseVal, pol.SimpleFractionDenoms, pol.SimpleFractionEpsilon) {
			return "simple-fraction-like"
		}
		return "eligible"
	}
	if len(frac) < pol.MinExistingDecimals {
		return "too-few-decimals"
	}
	v, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		return "malformed"
	}
	if v < 0 {
		v = -v
	}
	baseVal := roundTo(v, pol.VisiblePrecision)
	if pol.SkipIntegerLike && isNearInteger(baseVal, pol.IntegerEpsilon) {
		return "integer-like"
	}
	if pol.SkipSimpleFractions && isNearSimpleFraction(baseVal, pol.SimpleFractionDenoms, pol.SimpleFractionEpsilon) {
		return "simple-fraction-like"
	}
	return "eligible"
}

type numericStyleStats struct {
	Total          int
	IntegerTokens  int
	DecimalBuckets [10]int // 0 integer, 1..8 exact decimals, 9 = 9+
	MagLabels      []string
	MagCounts      []int
}

func collectNumericStyle(svg string) numericStyleStats {
	labels := []string{"0", "<1e-6", "1e-6..1e-5", "1e-5..1e-4", "1e-4..1e-3", "1e-3..1e-2", "1e-2..1e-1", "1e-1..1", "1..10", "10..100", "100..1k", "1k..10k", "10k..100k", "100k..1M", ">=1M"}
	st := numericStyleStats{MagLabels: labels, MagCounts: make([]int, len(labels))}
	for _, pm := range pathDRe.FindAllStringSubmatchIndex(svg, -1) {
		if len(pm) < 12 || pm[8] < 0 || pm[9] < 0 {
			continue
		}
		d := svg[pm[8]:pm[9]]
		if pm[12] >= 0 && pm[13] >= 0 {
			d = svg[pm[12]:pm[13]]
		}
		for _, m := range numberRe.FindAllString(d, -1) {
			st.Total++
			st.DecimalBuckets[decimalBucket(m)]++
			if decimalBucket(m) == 0 {
				st.IntegerTokens++
			}
			v, err := strconv.ParseFloat(m, 64)
			if err != nil {
				continue
			}
			if v < 0 {
				v = -v
			}
			idx := magnitudeBucket(v)
			if idx >= 0 && idx < len(st.MagCounts) {
				st.MagCounts[idx]++
			}
		}
	}
	return st
}

func decimalBucket(tok string) int {
	// Count lexical decimal places before exponent. Integer tokens are bucket 0;
	// 9 means 9 or more decimals. This intentionally tracks how the SVG looks,
	// not how the value parses numerically.
	t := strings.TrimSpace(tok)
	if i := strings.IndexAny(t, "eE"); i >= 0 {
		t = t[:i]
	}
	if dot := strings.IndexByte(t, '.'); dot >= 0 {
		n := len(t) - dot - 1
		n = max(n, 0)
		if n > 9 {
			return 9
		}
		return n
	}
	return 0
}

func magnitudeBucket(v float64) int {
	if v == 0 {
		return 0
	}
	if v < 1e-6 {
		return 1
	}
	if v < 1e-5 {
		return 2
	}
	if v < 1e-4 {
		return 3
	}
	if v < 1e-3 {
		return 4
	}
	if v < 1e-2 {
		return 5
	}
	if v < 1e-1 {
		return 6
	}
	if v < 1 {
		return 7
	}
	if v < 10 {
		return 8
	}
	if v < 100 {
		return 9
	}
	if v < 1000 {
		return 10
	}
	if v < 10000 {
		return 11
	}
	if v < 100000 {
		return 12
	}
	if v < 1000000 {
		return 13
	}
	return 14
}

func printNumericHistograms(svg string, width int) {
	if width < 8 {
		width = 32
	}
	st := collectNumericStyle(svg)
	fmt.Printf("numeric style histograms (path coordinates, width=%d)\n", width)
	fmt.Printf("  total numeric tokens:      %d\n", st.Total)
	if st.Total == 0 {
		return
	}
	fmt.Println("  decimal precision:")
	labels := []string{"integer", "1 decimal", "2 decimals", "3 decimals", "4 decimals", "5 decimals", "6 decimals", "7 decimals", "8 decimals", "9+ decimals"}
	for i, c := range st.DecimalBuckets {
		if c == 0 {
			continue
		}
		fmt.Printf("    %-12s %s %d\n", labels[i], histBar(c, st.Total, width), c)
	}
	maxMag := maxIntSlice(st.MagCounts)
	fmt.Println("  coordinate magnitude:")
	for i, c := range st.MagCounts {
		if c == 0 {
			continue
		}
		fmt.Printf("    %-12s %s %d\n", st.MagLabels[i], histBar(c, maxMag, width), c)
	}
}

func maxIntSlice(xs []int) int {
	m := 0
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	if m < 1 {
		m = 1
	}
	return m
}

func histBar(value, maxValue, width int) string {
	if value <= 0 || maxValue <= 0 || width <= 0 {
		return ""
	}
	// Horizontal bars use full block units for readability in terminals. The
	// value is rounded up so small nonzero buckets remain visible.
	n := int(math.Ceil(float64(value) / float64(maxValue) * float64(width)))
	n = max(n, 1)
	n = min(n, width)
	return strings.Repeat("█", n)
}

func printCarrierBreakdown(svg string, pol carrierPolicy) CarrierAnalysis {
	a := analyzeCarriers(svg, pol)
	fmt.Printf("eligible natural carriers: %d\n", a.Eligible)
	fmt.Printf("natural byte capacity:     %d bytes\n", a.Eligible)
	fmt.Printf("path numeric values:       %d\n", a.TotalPathNumbers)
	fmt.Printf("skipped no decimal:        %d\n", a.NoDecimal)
	fmt.Printf("skipped scientific:        %d\n", a.Scientific)
	fmt.Printf("skipped too few decimals:  %d\n", a.TooFewDecimals)
	fmt.Printf("skipped integer-like:      %d\n", a.IntegerLike)
	fmt.Printf("skipped simple fractions:  %d\n", a.SimpleFractionLike)
	fmt.Printf("skipped malformed/other:   %d\n", a.Malformed)
	return a
}

func printCarrierMap(svg string, a CarrierAnalysis, width int, mode string) {
	if width < 8 {
		width = 40
	}
	if len(svg) == 0 {
		return
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "dominant"
	}
	fmt.Printf("carrier map by file offset (%d cells, mode=%s)\n", width, mode)
	if mode == "multi" {
		printCarrierMapLine("eligible", svg, a, width, func(k byte) bool { return k == kindEligible }, "◆")
		printCarrierMapLine("skipped ", svg, a, width, func(k byte) bool { return k == kindTooFew || k == kindGrid }, "△")
		printCarrierMapLine("numeric ", svg, a, width, func(k byte) bool { return k == kindNumeric }, "·")
		fmt.Println("legend: ◆ eligible △ skipped/no-decimal/grid-like · numeric/non-carrier")
		return
	}
	cells := make([]byte, width)
	for i := range cells {
		cells[i] = 'n'
	}
	priority := map[byte]int{'n': 0, kindNumeric: 1, kindTooFew: 2, kindGrid: 3, kindEligible: 4}
	if mode == "skipped" {
		priority = map[byte]int{'n': 0, kindEligible: 1, kindNumeric: 1, kindTooFew: 3, kindGrid: 4}
	}
	if mode == "eligible" {
		priority = map[byte]int{'n': 0, kindNumeric: 1, kindTooFew: 1, kindGrid: 1, kindEligible: 4}
	}
	for _, tm := range a.TokenOffsets {
		cell := int((int64(tm.Offset) * int64(width)) / int64(len(svg)))
		cell = max(cell, 0)
		if cell >= width {
			cell = width - 1
		}
		if priority[tm.Kind] >= priority[cells[cell]] {
			cells[cell] = tm.Kind
		}
	}
	fmt.Printf("0x%06x ┃", 0)
	for _, c := range cells {
		fmt.Print(mapRune(c))
	}
	fmt.Printf("┃ 0x%06x\n", len(svg))
	fmt.Println("legend: ░ no path numbers · numeric/non-carrier ○ too few/no decimals △ integer/fraction-like ◆ eligible")
}

func printCarrierMapLine(label, svg string, a CarrierAnalysis, width int, pred func(byte) bool, glyph string) {
	cells := make([]bool, width)
	for _, tm := range a.TokenOffsets {
		if !pred(tm.Kind) {
			continue
		}
		cell := int((int64(tm.Offset) * int64(width)) / int64(len(svg)))
		cell = max(cell, 0)
		if cell >= width {
			cell = width - 1
		}
		cells[cell] = true
	}
	fmt.Printf("%s 0x%06x ┃", label, 0)
	for _, ok := range cells {
		if ok {
			fmt.Print(glyph)
		} else {
			fmt.Print("░")
		}
	}
	fmt.Printf("┃ 0x%06x\n", len(svg))
}

func mapRune(c byte) string {
	switch c {
	case 'n':
		return "░"
	case kindNumeric:
		return "·"
	case kindTooFew:
		return "○"
	case kindGrid:
		return "△"
	case kindEligible:
		return "◆"
	default:
		return "?"
	}
}

func countEligiblePathNumbers(svg string, pol carrierPolicy) int {
	return analyzeCarriers(svg, pol).Eligible
}

func eligibleCarrier(tok string, pol carrierPolicy) bool {
	return carrierReason(tok, pol) == "eligible"
}

func allZeros(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}

func parseDenominators(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	var out []int
	seen := map[int]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 1024 {
			return nil, fmt.Errorf("invalid denominator %q in --simple-fraction-denominators", p)
		}
		if !seen[n] {
			out = append(out, n)
			seen[n] = true
		}
	}
	return out, nil
}

func isNearInteger(v, eps float64) bool {
	if eps <= 0 {
		return false
	}
	return math.Abs(v-math.Round(v)) <= eps
}

func isNearSimpleFraction(v float64, denoms []int, eps float64) bool {
	if eps <= 0 {
		return false
	}
	frac := v - math.Floor(v)
	for _, d := range denoms {
		for n := 0; n <= d; n++ {
			target := float64(n) / float64(d)
			if math.Abs(frac-target) <= eps || math.Abs((frac+1)-target) <= eps || math.Abs(frac-(target+1)) <= eps {
				return true
			}
		}
	}
	return false
}

func encodeStreamIntoSVG(svg string, stream []byte, pol carrierPolicy) (string, int, error) {
	idx := 0
	out := pathDRe.ReplaceAllStringFunc(svg, func(pathTag string) string {
		if idx >= len(stream) {
			return pathTag
		}
		parts := pathDRe.FindStringSubmatch(pathTag)
		if parts == nil {
			return pathTag
		}
		d := pathDFromMatch(parts)
		quote := `"`
		if strings.HasPrefix(parts[2], `'`) {
			quote = `'`
		}
		newD := numberRe.ReplaceAllStringFunc(d, func(tok string) string {
			if idx >= len(stream) || !eligibleCarrier(tok, pol) {
				return tok
			}
			b := stream[idx]
			enc := encodeNumber(tok, b, pol.VisiblePrecision)
			// Only consume this carrier if the encoded form round-trips. The visible
			// part can round to a whole number (and carrier byte 0 then makes the
			// token integer-like), which the decoder's skip-integer heuristic would
			// drop — an encoder/decoder disagreement that loses the byte. Skipping
			// such tokens keeps both sides in agreement by construction, at a small
			// capacity cost. (T-011)
			if got, ok := decodeNumber(enc, pol); !ok || got != b {
				return tok
			}
			idx++
			return enc
		})
		return "<path" + parts[1] + "d=" + quote + newD + quote + parts[7] + ">"
	})
	if idx < len(stream) {
		return "", idx, fmt.Errorf("insufficient path coordinate capacity: need %d have %d", len(stream), idx)
	}
	return out, idx, nil
}

func encodeNumber(tok string, b byte, visiblePrecision int) string {
	v, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		return tok
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	baseStr := fmt.Sprintf("%.*f", visiblePrecision, roundTo(v, visiblePrecision))
	if visiblePrecision == 0 {
		return fmt.Sprintf("%s%s.%03d", sign, baseStr, b)
	}
	return fmt.Sprintf("%s%s%03d", sign, baseStr, b)
}
func roundTo(v float64, prec int) float64 { p := math.Pow10(prec); return math.Round(v*p) / p }

func extractCarrierBytes(svg string, pol carrierPolicy) []byte {
	var out []byte
	for _, m := range pathDRe.FindAllStringSubmatch(svg, -1) {
		d := pathDFromMatch(m)
		for _, tok := range numberRe.FindAllString(d, -1) {
			if b, ok := decodeNumber(tok, pol); ok {
				out = append(out, b)
			}
		}
	}
	return out
}
func decodeNumber(tok string, pol carrierPolicy) (byte, bool) {
	if !eligibleCarrier(tok, pol) {
		return 0, false
	}
	s := strings.TrimSpace(tok)
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	_, frac, hasDot := strings.Cut(s, ".")
	if !hasDot {
		return 0, false
	}
	need := pol.VisiblePrecision + carrierDigits
	if len(frac) < need {
		return 0, false
	}
	tail := frac[pol.VisiblePrecision:need]
	v, err := strconv.Atoi(tail)
	if err != nil || v < 0 || v > 255 {
		return 0, false
	}
	return byte(v), true
}

// Geometry subdivision.
type pt struct{ x, y float64 }
type segment struct {
	cmd byte
	pts []pt
}

func subdivideSVGForCapacity(svg string, target int, pol carrierPolicy) (string, int, error) {
	addedTotal := 0
	out := pathDRe.ReplaceAllStringFunc(svg, func(pathTag string) string {
		if countEligiblePathNumbers(svg, pol)+addedTotal >= target {
			return pathTag
		}
		parts := pathDRe.FindStringSubmatch(pathTag)
		if parts == nil {
			return pathTag
		}
		d := pathDFromMatch(parts)
		needNow := target - (countEligiblePathNumbers(svg, pol) + addedTotal)
		newD, added, ok := subdividePathD(d, needNow, pol)
		if !ok || added == 0 {
			return pathTag
		}
		addedTotal += added
		quote := `"`
		if strings.HasPrefix(parts[2], `'`) {
			quote = `'`
		}
		return "<path" + parts[1] + "d=" + quote + newD + quote + parts[7] + ">"
	})
	return out, addedTotal, nil
}

func subdividePathD(d string, need int, pol carrierPolicy) (string, int, bool) {
	segs, ok := parsePathD(d)
	if !ok || len(segs) == 0 {
		return d, 0, false
	}
	added := 0
	for pass := 0; pass < 12 && added < need; pass++ {
		var next []segment
		cur := pt{}
		for _, s := range segs {
			if added >= need {
				next = append(next, s)
				continue
			}
			switch s.cmd {
			case 'M':
				next = append(next, s)
				if len(s.pts) > 0 {
					cur = s.pts[0]
				}
			case 'L':
				if len(s.pts) != 1 {
					next = append(next, s)
					break
				}
				mid := lerp(cur, s.pts[0], splitT(cur, s.pts[0]))
				next = append(next, segment{'L', []pt{mid}}, segment{'L', []pt{s.pts[0]}})
				added += 2
				cur = s.pts[0]
			case 'C':
				if len(s.pts) != 3 {
					next = append(next, s)
					break
				}
				c1, c2 := splitCubic(cur, s.pts[0], s.pts[1], s.pts[2], 0.5)
				next = append(next, c1, c2)
				added += 6
				cur = s.pts[2]
			case 'Q':
				if len(s.pts) != 2 {
					next = append(next, s)
					break
				}
				q1, q2 := splitQuadratic(cur, s.pts[0], s.pts[1], 0.5)
				next = append(next, q1, q2)
				added += 4
				cur = s.pts[1]
			default:
				next = append(next, s)
			}
		}
		segs = next
	}
	return serializePath(segs, pol.VisiblePrecision+carrierDigits), added, added > 0
}

func splitT(a, b pt) float64 { // deterministic non-half when it still produces a point on the same segment.
	dx := math.Abs(b.x - a.x)
	dy := math.Abs(b.y - a.y)
	if math.Mod(math.Floor(dx+dy), 2) == 0 {
		return 0.382
	}
	return 0.618
}
func lerp(a, b pt, t float64) pt { return pt{a.x + (b.x-a.x)*t, a.y + (b.y-a.y)*t} }
func splitCubic(p0, p1, p2, p3 pt, t float64) (segment, segment) {
	a := lerp(p0, p1, t)
	b := lerp(p1, p2, t)
	c := lerp(p2, p3, t)
	d := lerp(a, b, t)
	e := lerp(b, c, t)
	f := lerp(d, e, t)
	return segment{'C', []pt{a, d, f}}, segment{'C', []pt{e, c, p3}}
}
func splitQuadratic(p0, p1, p2 pt, t float64) (segment, segment) {
	a := lerp(p0, p1, t)
	b := lerp(p1, p2, t)
	c := lerp(a, b, t)
	return segment{'Q', []pt{a, c}}, segment{'Q', []pt{b, p2}}
}

func parsePathD(d string) ([]segment, bool) {
	toks := pathLexRe.FindAllString(d, -1)
	if len(toks) == 0 {
		return nil, false
	}
	i := 0
	cmd := byte(0)
	cur := pt{}
	sub := pt{}
	var segs []segment
	isCmd := func(s string) bool { return len(s) == 1 && strings.ContainsRune("AaCcHhLlMmQqSsTtVvZz", rune(s[0])) }
	read := func() (float64, bool) {
		if i >= len(toks) || isCmd(toks[i]) {
			return 0, false
		}
		v, err := strconv.ParseFloat(toks[i], 64)
		if err != nil {
			return 0, false
		}
		i++
		return v, true
	}
	for i < len(toks) {
		if isCmd(toks[i]) {
			cmd = toks[i][0]
			i++
		}
		if cmd == 0 {
			return nil, false
		}
		rel := cmd >= 'a' && cmd <= 'z'
		up := cmd
		if rel {
			up -= 32
		}
		switch up {
		case 'M':
			x, ok := read()
			if !ok {
				return nil, false
			}
			y, ok := read()
			if !ok {
				return nil, false
			}
			if rel {
				x += cur.x
				y += cur.y
			}
			cur = pt{x, y}
			sub = cur
			segs = append(segs, segment{'M', []pt{cur}})
			cmd = 'L'
			if rel {
				cmd = 'l'
			}
		case 'L':
			x, ok := read()
			if !ok {
				return nil, false
			}
			y, ok := read()
			if !ok {
				return nil, false
			}
			if rel {
				x += cur.x
				y += cur.y
			}
			cur = pt{x, y}
			segs = append(segs, segment{'L', []pt{cur}})
		case 'H':
			x, ok := read()
			if !ok {
				return nil, false
			}
			if rel {
				x += cur.x
			}
			cur = pt{x, cur.y}
			segs = append(segs, segment{'L', []pt{cur}})
		case 'V':
			y, ok := read()
			if !ok {
				return nil, false
			}
			if rel {
				y += cur.y
			}
			cur = pt{cur.x, y}
			segs = append(segs, segment{'L', []pt{cur}})
		case 'C':
			x1, ok := read()
			if !ok {
				return nil, false
			}
			y1, ok := read()
			if !ok {
				return nil, false
			}
			x2, ok := read()
			if !ok {
				return nil, false
			}
			y2, ok := read()
			if !ok {
				return nil, false
			}
			x, ok := read()
			if !ok {
				return nil, false
			}
			y, ok := read()
			if !ok {
				return nil, false
			}
			if rel {
				x1 += cur.x
				y1 += cur.y
				x2 += cur.x
				y2 += cur.y
				x += cur.x
				y += cur.y
			}
			p1 := pt{x1, y1}
			p2 := pt{x2, y2}
			p := pt{x, y}
			segs = append(segs, segment{'C', []pt{p1, p2, p}})
			cur = p
		case 'Q':
			x1, ok := read()
			if !ok {
				return nil, false
			}
			y1, ok := read()
			if !ok {
				return nil, false
			}
			x, ok := read()
			if !ok {
				return nil, false
			}
			y, ok := read()
			if !ok {
				return nil, false
			}
			if rel {
				x1 += cur.x
				y1 += cur.y
				x += cur.x
				y += cur.y
			}
			p1 := pt{x1, y1}
			p := pt{x, y}
			segs = append(segs, segment{'Q', []pt{p1, p}})
			cur = p
		case 'Z':
			segs = append(segs, segment{'Z', nil})
			cur = sub
			cmd = 0
		default:
			return nil, false
		}
	}
	return segs, true
}

func serializePath(segs []segment, prec int) string {
	var b strings.Builder
	for _, s := range segs {
		b.WriteByte(s.cmd)
		for _, p := range s.pts {
			b.WriteByte(' ')
			b.WriteString(fmtNum(p.x, prec))
			b.WriteByte(' ')
			b.WriteString(fmtNum(p.y, prec))
		}
		b.WriteByte(' ')
	}
	return strings.TrimSpace(b.String())
}
func fmtNum(v float64, prec int) string { return fmt.Sprintf("%.*f", prec, v) }

func injectCarrierPath(svg string, carriers int, pol carrierPolicy) (string, error) {
	if carriers <= 0 {
		return svg, nil
	}
	if !svgCloseRe.MatchString(svg) {
		return "", errors.New("input does not contain closing </svg>")
	}
	style := strings.ToLower(strings.TrimSpace(pol.InvisibleCarrierStyle))
	if style == "" {
		style = "defs"
	}
	if style == "opacity" {
		return injectOpacityCarrierPath(svg, carriers)
	}
	return injectDefsCarrierPaths(svg, carriers)
}

func injectOpacityCarrierPath(svg string, carriers int) (string, error) {
	var d strings.Builder
	for i := range carriers {
		fmt.Fprintf(&d, "L %.6f %.6f ", 3.781+float64(i%997)*0.013, 7.419+float64((i*37)%997)*0.011)
	}
	carrier := "\n  <g opacity=\"0\" pointer-events=\"none\" aria-hidden=\"true\"><path fill=\"none\" stroke=\"none\" d=\"M 3.781000 7.419000 " + d.String() + "\"/></g>\n"
	loc := svgCloseRe.FindStringIndex(svg)
	return svg[:loc[0]] + carrier + svg[loc[0]:], nil
}

func injectDefsCarrierPaths(svg string, carriers int) (string, error) {
	// XML-shaped fallback: put carrier paths in <defs>, split into path-sized
	// chunks that roughly mimic ordinary SVG path elements instead of one giant
	// opacity=0 line. <defs> is non-rendering SVG structure, so this remains
	// visually stable without literal hidden/opacity attributes.
	loc := svgCloseRe.FindStringIndex(svg)
	if loc == nil {
		return "", errors.New("input does not contain closing </svg>")
	}
	lineTarget := estimateCarrierPathLineTarget(svg)
	lineTarget = max(lineTarget, 240)
	lineTarget = min(lineTarget, 1600)
	// Each L command with two %.6f values is roughly 24-34 chars. Keep chunks
	// comfortably under the target so the output doesn't create monster lines.
	perPath := lineTarget / 34
	perPath = max(perPath, 8)
	perPath = min(perPath, 48)
	var b strings.Builder
	b.WriteString("\n  <defs>\n")
	idBase := stableXMLID(svg)
	for made, pathIdx := 0, 0; made < carriers; pathIdx++ {
		n := min(perPath, carriers-made)
		x0 := 3.781 + float64((pathIdx*53)%997)*0.013
		y0 := 7.419 + float64((pathIdx*97)%997)*0.011
		fmt.Fprintf(&b, "    <path id=\"%s-c%03d\" d=\"M %.6f %.6f", idBase, pathIdx, x0, y0)
		for i := range n {
			j := made + i
			x := 3.781 + float64(j%997)*0.013
			y := 7.419 + float64((j*37)%997)*0.011
			fmt.Fprintf(&b, " L %.6f %.6f", x, y)
		}
		b.WriteString("\"/>\n")
		made += n
	}
	b.WriteString("  </defs>\n")
	return svg[:loc[0]] + b.String() + svg[loc[0]:], nil
}

func estimateCarrierPathLineTarget(svg string) int {
	lines := strings.Split(svg, "\n")
	var lens []int
	for _, ln := range lines {
		if strings.Contains(ln, "<path") && strings.Contains(ln, "d=") {
			l := len(ln)
			if l > 0 {
				lens = append(lens, l)
			}
		}
	}
	if len(lens) == 0 {
		return 640
	}
	sort.Ints(lens)
	p := lens[(len(lens)*75)/100]
	if p < 240 {
		return 240
	}
	return p
}

func stableXMLID(svg string) string {
	sum := sha256.Sum256([]byte(svg))
	return fmt.Sprintf("svgsteg-%x", sum[:3])
}

func runCarrierElectionSelfTests(opt options) error {
	fmt.Println("self-test: carrier-election threshold sanity")
	base := policyFrom(opt, embeddedCarrierElectionSVG())
	// Use the same visible precision as runtime defaults, but force the intended
	// policy knobs for this sanity test so CLI changes do not hide regressions.
	strict := base
	strict.MinExistingDecimals = 3
	strict.SkipIntegerLike = true
	strict.SkipSimpleFractions = true
	strict.IntegerEpsilon = 0.000001
	strict.SimpleFractionEpsilon = 0.000001
	strict.SimpleFractionDenoms = []int{2, 4}

	noEpsilon := strict
	noEpsilon.IntegerEpsilon = 0
	noEpsilon.SimpleFractionEpsilon = 0

	loose := noEpsilon
	loose.MinExistingDecimals = 1
	loose.SkipIntegerLike = false
	loose.SkipSimpleFractions = false

	if err := assertCarrierMonotonic("embedded-style-mix", embeddedCarrierElectionSVG(), strict, noEpsilon, loose); err != nil {
		return err
	}
	if err := assertRelativeEpsilonBehavior(opt); err != nil {
		return err
	}
	if err := assertDecimalizeIntegersBehavior(opt); err != nil {
		return err
	}

	if opt.inPath == "" {
		fmt.Println("  note: no --in SVG supplied; skipping user-SVG carrier-election sanity. Embedded SVG checks still ran.")
		return nil
	}
	b, err := os.ReadFile(opt.inPath)
	if err != nil {
		return fmt.Errorf("read self-test --in SVG: %w", err)
	}
	// Real SVGs can legitimately have no grid-like values or low-precision values,
	// so this check reports monotonicity and only fails on impossible decreases.
	name := "user-svg"
	cStrict := countEligiblePathNumbers(string(b), strict)
	cNoEps := countEligiblePathNumbers(string(b), noEpsilon)
	cLoose := countEligiblePathNumbers(string(b), loose)
	fmt.Printf("  %s carriers: strict=%d no-epsilon=%d loose=%d\n", name, cStrict, cNoEps, cLoose)
	if cNoEps < cStrict || cLoose < cNoEps {
		return fmt.Errorf("%s carrier counts are not monotonic: strict=%d no-epsilon=%d loose=%d", name, cStrict, cNoEps, cLoose)
	}
	if cStrict == cNoEps && cNoEps == cLoose {
		fmt.Println("  note: user SVG carrier count did not change under relaxed thresholds; it may lack integer/fraction-like or low-decimal path coordinates.")
	}
	return nil
}

func assertRelativeEpsilonBehavior(opt options) error {
	large := embeddedLargeViewBoxEpsilonSVG()
	absOpt := opt
	absOpt.minExistingDecimals = 6
	absOpt.skipIntegerLike = true
	absOpt.skipSimpleFractions = true
	absOpt.integerEpsilon = 0.000000001
	absOpt.simpleFractionEpsilon = 0.000000001
	absOpt.integerEpsilonMode = "absolute"
	absOpt.simpleFractionEpsilonMode = "absolute"
	relOpt := absOpt
	relOpt.integerEpsilonMode = "relative-width"
	relOpt.simpleFractionEpsilonMode = "relative-width"
	absPol := policyFrom(absOpt, large)
	relPol := policyFrom(relOpt, large)
	cAbs := countEligiblePathNumbers(large, absPol)
	cRel := countEligiblePathNumbers(large, relPol)
	fmt.Printf("  relative-epsilon large-viewBox carriers: absolute=%d relative-width=%d effective-relative=%g\n", cAbs, cRel, relPol.IntegerEpsilon)
	if cAbs <= cRel {
		return fmt.Errorf("relative epsilon test expected absolute carriers > relative carriers, got absolute=%d relative=%d", cAbs, cRel)
	}
	if relPol.IntegerEpsilon <= absPol.IntegerEpsilon {
		return fmt.Errorf("relative epsilon test expected effective relative epsilon > absolute epsilon")
	}
	return nil
}

func assertCarrierMonotonic(name, svg string, strict, noEpsilon, loose carrierPolicy) error {
	cStrict := countEligiblePathNumbers(svg, strict)
	cNoEps := countEligiblePathNumbers(svg, noEpsilon)
	cLoose := countEligiblePathNumbers(svg, loose)
	fmt.Printf("  %s carriers: strict=%d no-epsilon=%d loose=%d\n", name, cStrict, cNoEps, cLoose)
	if !(cStrict < cNoEps && cNoEps < cLoose) {
		return fmt.Errorf("%s expected strict < no-epsilon < loose carrier counts, got %d < %d < %d", name, cStrict, cNoEps, cLoose)
	}
	return nil
}

func embeddedCarrierElectionSVG() string {
	// This intentionally mixes carrier types:
	// - irregular 3-decimal coordinates that should pass strict policy
	// - integer-ish decimals such as 4.000 that strict policy should reject
	// - simple fractions such as .250/.500/.750 that strict policy should reject
	// - low-decimal coordinates such as 15.7 and 16.12 that only become carriers
	//   when --min-existing-decimals is relaxed.
	// It is not meant to be pretty; it is a deterministic calibration target.
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360">` + "\n")
	b.WriteString(`  <path fill="none" stroke="#111" d="`)
	b.WriteString(`M 3.782 7.419 C 11.137 19.283 27.641 33.817 45.913 51.229 `)
	b.WriteString(`L 61.347 72.589 C 83.719 91.443 105.337 122.681 144.913 159.277 `)
	b.WriteString(`L 4.000 8.000 L 12.250 16.500 L 24.750 32.125 `)
	b.WriteString(`C 40.000 44.250 48.500 52.750 64.000 68.250 `)
	b.WriteString(`L 15.7 21.3 L 16.12 22.34 C 31.4 41.6 59.81 63.92 71.2 89.3 `)
	b.WriteString(`C 101.781 117.394 133.829 149.618 171.437 193.286 `)
	b.WriteString(`"/>` + "\n")
	b.WriteString(`</svg>` + "\n")
	return b.String()
}

func embeddedLargeViewBoxEpsilonSVG() string {
	return `<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000" viewBox="-1000000 -1000000 2000000 2000000">
  <path fill="none" stroke="#000" d="M 4.001100 7.123456 L 10.998900 8.876543 C 12.251100 16.501100 24.748900 32.126100 48.333333 96.666667 L 101.123456 202.654321"/>
</svg>`
}

func assertDecimalizeIntegersBehavior(opt options) error {
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path d="M 1 2 L 3 4 L 5.123 6.456"/></svg>`
	baseOpt := opt
	baseOpt.minExistingDecimals = 0
	baseOpt.skipIntegerLike = false
	baseOpt.skipSimpleFractions = false
	baseOpt.allowDecimalizeIntegers = false
	without := countEligiblePathNumbers(svg, policyFrom(baseOpt, svg))
	baseOpt.allowDecimalizeIntegers = true
	with := countEligiblePathNumbers(svg, policyFrom(baseOpt, svg))
	fmt.Printf("  decimalize-integers carriers: disabled=%d enabled=%d\n", without, with)
	if with <= without {
		return fmt.Errorf("expected --allow-decimalize-integers to expose more carriers, got disabled=%d enabled=%d", without, with)
	}
	return nil
}

func runSelfTest(opt options) error {
	if err := runCarrierElectionSelfTests(opt); err != nil {
		return err
	}
	fmt.Println("self-test: SVG steganography randomized size sweep")
	sizes := []int{16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}
	seed := time.Now().UnixNano()
	r := mrand.New(mrand.NewSource(seed))
	pass := []byte("self-test-passphrase")
	cases := 0
	for _, size := range sizes {
		for run := 0; run < opt.selfTestRuns; run++ {
			payload := make([]byte, size)
			if _, err := io.ReadFull(rand.Reader, payload); err != nil {
				return err
			}
			svg := []byte(randomSVG(r, size, run))
			encoded, stats, err := EncodeSVG(svg, payload, pass, opt)
			if err != nil {
				return fmt.Errorf("size=%d run=%d encode failed: %w", size, run, err)
			}
			decoded, err := DecodeSVG(encoded, pass, policyFrom(opt, string(encoded)))
			if err != nil {
				return fmt.Errorf("size=%d run=%d decode failed: %w", size, run, err)
			}
			if !bytes.Equal(payload, decoded) {
				return fmt.Errorf("size=%d run=%d payload mismatch", size, run)
			}
			if _, err := DecodeSVG(encoded, []byte("wrong-pass"), policyFrom(opt, string(encoded))); err == nil {
				return fmt.Errorf("size=%d run=%d wrong passphrase unexpectedly decoded", size, run)
			}
			tampered, changed := tamperFirstCarrierDigit(encoded, policyFrom(opt, string(encoded)))
			if changed {
				if _, err := DecodeSVG(tampered, pass, policyFrom(opt, string(tampered))); err == nil {
					return fmt.Errorf("size=%d run=%d tamper unexpectedly decoded", size, run)
				}
			}
			fmt.Printf("  ok size=%5d run=%d stream=%5d natural=%4d subdiv=%5d invis=%5d\n", size, run, stats.StreamBytes, stats.NaturalCarriers, stats.SubdivisionCarriers, stats.InvisibleCarriers)
			cases++
		}
	}
	fmt.Printf("PASS: %d cases; seed=%d; max_payload=16384 bytes\n", cases, seed)
	return nil
}

func tamperFirstCarrierDigit(svg []byte, pol carrierPolicy) ([]byte, bool) {
	s := string(svg)
	for _, loc := range numberRe.FindAllStringIndex(s, -1) {
		tok := s[loc[0]:loc[1]]
		if _, ok := decodeNumber(tok, pol); !ok {
			continue
		}
		dot := strings.IndexByte(tok, '.')
		if dot < 0 {
			continue
		}
		abs := loc[0] + dot + 1 + pol.VisiblePrecision + carrierDigits - 1
		out := append([]byte(nil), svg...)
		if out[abs] >= '0' && out[abs] <= '8' {
			out[abs]++
		} else if out[abs] == '9' {
			out[abs] = '8'
		} else {
			continue
		}
		return out, true
	}
	return svg, false
}

func randomSVG(r *mrand.Rand, size, run int) string {
	w := 128 + r.Intn(512)
	h := 128 + r.Intn(512)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`+"\n", w, h, w, h)
	fmt.Fprintf(&b, `  <rect x="0" y="0" width="%d" height="%d" fill="#%06x"/>`+"\n", w, h, r.Intn(0xffffff))
	paths := 1 + r.Intn(4)
	for range paths {
		x := float64(r.Intn(w)) + r.Float64()
		y := float64(r.Intn(h)) + r.Float64()
		b.WriteString(`  <path fill="none" stroke="#111" d="`)
		fmt.Fprintf(&b, "M %.3f %.3f ", x, y)
		segs := 2 + r.Intn(8)
		for range segs {
			if r.Intn(2) == 0 {
				x = float64(r.Intn(w)) + r.Float64()
				y = float64(r.Intn(h)) + r.Float64()
				fmt.Fprintf(&b, "L %.3f %.3f ", x, y)
			} else {
				fmt.Fprintf(&b, "C %.3f %.3f %.3f %.3f %.3f %.3f ", float64(r.Intn(w))+r.Float64(), float64(r.Intn(h))+r.Float64(), float64(r.Intn(w))+r.Float64(), float64(r.Intn(h))+r.Float64(), float64(r.Intn(w))+r.Float64(), float64(r.Intn(h))+r.Float64())
			}
		}
		b.WriteString(`"/>` + "\n")
	}
	fmt.Fprintf(&b, `  <!-- selftest size=%d run=%d -->`+"\n", size, run)
	b.WriteString(`</svg>` + "\n")
	return b.String()
}
