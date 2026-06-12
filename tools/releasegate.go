//go:build ignore

// releasegate.go — zero-dependency release gate for svgsteg (BACKLOG T-005/T-001).
//
// Runs every proof we rely on as a single reproducible pass and exits non-zero if
// any check fails. Pure standard library; uses os/exec to drive the go toolchain.
// This is DEV TOOLING and is never compiled into svgsteg.exe.
//
// Run:  go run tools/releasegate.go
//
// Checks (core set; IOC/entropy/SBOM scans are deferred follow-ups):
//   1. release build      — CGO off, -trimpath -ldflags="-s -w"
//   2. reproducible build — build twice, assert byte-identical (non-determinism = tampering)
//   3. nm invariants      — 0 net.* / crypto/tls / net/http / os/exec / plugin symbols
//   4. brotli provenance  — third_party/brotli == upstream minus http.go (custody intact)
//   5. govulncheck        — no reachable known vulnerabilities
//   6. go vet             — clean
//   7. go test ./...      — unit/fuzz-seed tests (picks up T-008/T-009 as they land)
//   8. integrity (SRI)    — every static include in web/*.html carries a matching hash (T-063)
//   9. capability gate    — neither artifact links a NEW package vs the baseline (T-065)
//  10. pin gate           — every workflow `uses:` pinned to a 40-hex commit SHA (T-057)

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const releaseBin = "svgsteg.exe"

var buildArgs = []string{"build", "-trimpath", "-ldflags=-s -w", "-mod=vendor"}

type result struct {
	name   string
	pass   bool
	detail string
}

var results []result

func record(name string, pass bool, detail string) {
	results = append(results, result{name, pass, detail})
	status := "PASS"
	if !pass {
		status = "FAIL"
	}
	fmt.Printf("  [%s] %-20s %s\n", status, name, detail)
}

func run(env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func buildTo(out string) (string, error) {
	args := append(append([]string{}, buildArgs...), "-o", out, "./cmd/svgsteg")
	env := append(os.Environ(), "CGO_ENABLED=0")
	return run(env, "go", args...)
}

func sha256File(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func main() {
	fmt.Println("== svgsteg release gate ==")

	// 1) release build (also the artifact the later checks inspect)
	if out, err := buildTo(releaseBin); err != nil {
		record("release build", false, "FAILED: "+lastLine(out))
		summary()
		os.Exit(1) // nothing else can run without a binary
	}
	record("release build", true, releaseBin+" built (-s -w -trimpath, CGO off)")

	// 2) reproducible build
	const tmp = "svgsteg.repro.tmp"
	defer os.Remove(tmp)
	if out, err := buildTo(tmp); err != nil {
		record("reproducible build", false, "2nd build FAILED: "+lastLine(out))
	} else {
		h1, _ := sha256File(releaseBin)
		h2, _ := sha256File(tmp)
		record("reproducible build", h1 != "" && h1 == h2,
			fmt.Sprintf("sha256 %s == %s", short(h1), short(h2)))
	}

	// 3) nm invariants — the release build is stripped (-s -w removes the symbol
	// table), so build a NON-stripped twin from identical source/flags to inspect.
	// Stripping changes names, not linked code, so net=0 on the twin proves it for
	// the stripped artifact too.
	const nmBin = "svgsteg.nm.tmp"
	defer os.Remove(nmBin)
	nmEnv := append(os.Environ(), "CGO_ENABLED=0")
	if out, err := run(nmEnv, "go", "build", "-trimpath", "-mod=vendor", "-o", nmBin, "./cmd/svgsteg"); err != nil {
		record("nm invariants", false, "symbol-build failed: "+lastLine(out))
	} else if nmOut, err := run(nil, "go", "tool", "nm", nmBin); err != nil {
		record("nm invariants", false, "go tool nm failed: "+lastLine(nmOut))
	} else {
		forbidden := []struct {
			label string
			re    *regexp.Regexp
		}{
			{"net.*", regexp.MustCompile(`(^|\s)net\.[A-Z(]`)},
			{"crypto/tls", regexp.MustCompile(`crypto/tls\.`)},
			{"net/http", regexp.MustCompile(`net/http\.`)},
			{"os/exec", regexp.MustCompile(`os/exec\.`)},
			{"plugin", regexp.MustCompile(`(^|\s)plugin\.[A-Z]`)},
		}
		var hits []string
		for _, f := range forbidden {
			if n := len(f.re.FindAllString(nmOut, -1)); n > 0 {
				hits = append(hits, fmt.Sprintf("%s=%d", f.label, n))
			}
		}
		if len(hits) == 0 {
			record("nm invariants", true, "no net/exec/plugin symbols linked")
		} else {
			record("nm invariants", false, "FORBIDDEN SYMBOLS: "+strings.Join(hits, ", "))
		}
	}

	// 4) brotli provenance (chain of custody)
	out, _ := run(nil, "go", "run", "tools/verify_brotli_provenance.go")
	record("brotli provenance", strings.Contains(out, "PASS:"),
		"custody "+passWord(strings.Contains(out, "PASS:")))

	// 4b) oksvg provenance (custody for the stroke-width patch atop fyne-io/oksvg@v0.2.0)
	outO, _ := run(nil, "go", "run", "tools/verify_oksvg_provenance.go")
	record("oksvg provenance", strings.Contains(outO, "PASS:"),
		"custody "+passWord(strings.Contains(outO, "PASS:")))

	// 5) govulncheck
	gv, _ := run(nil, "govulncheck", "./...")
	clean := strings.Contains(gv, "No vulnerabilities found")
	gvDetail := "no reachable vulnerabilities"
	if !clean {
		gvDetail = "VULNS FOUND: " + lastLine(gv)
	}
	record("govulncheck", clean, gvDetail)

	// 6) go vet
	if out, err := run(nil, "go", "vet", "-mod=vendor", "./..."); err != nil {
		record("go vet", false, "issues: "+lastLine(out))
	} else {
		record("go vet", true, "clean")
	}

	// 7) go test ./... (units + fuzz seed corpus; future T-008/T-009 land here)
	if out, err := run(nil, "go", "test", "-mod=vendor", "./..."); err != nil {
		record("go test ./...", false, "FAILED: "+lastLine(out))
	} else {
		record("go test ./...", true, "tests pass (incl. fuzz seed corpus)")
	}

	// 8) integrity gate — every static <script>/<link rel=stylesheet> in web/*.html
	// must carry a matching SRI hash (T-063).
	ig, igErr := run(nil, "go", "run", "tools/integritygate.go", "verify")
	record("integrity (SRI)", igErr == nil, lastLine(ig))

	// 9) capability gate — neither shipped artifact (CLI or wasm) may link a NEW package
	// versus the committed baseline (capgate); the supply-chain "grew a capability" tripwire.
	cg, cgErr := run(nil, "go", "run", "tools/capgate.go")
	record("capability gate", cgErr == nil, lastLine(cg))

	// 10) pin gate — every `uses:` in .github/workflows/** is pinned to a 40-hex commit SHA
	// (pingate); the moved-tag (tj-actions / Trivy-Aqua) tripwire.
	pg, pgErr := run(nil, "go", "run", "tools/pingate.go")
	record("pin gate", pgErr == nil, lastLine(pg))

	summary()
}

func passWord(ok bool) string {
	if ok {
		return "OK"
	}
	return "NOT-OK"
}

func summary() {
	failed := 0
	for _, r := range results {
		if !r.pass {
			failed++
		}
	}
	fmt.Printf("\n== %d/%d checks passed ==\n", len(results)-failed, len(results))
	if failed > 0 {
		fmt.Printf("RELEASE GATE: FAIL (%d check(s) failed)\n", failed)
		os.Exit(1)
	}
	fmt.Println("RELEASE GATE: PASS")
}
