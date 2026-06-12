//go:build ignore

// capgate — capability-regression gate. Snapshots the transitive package surface compiled
// into each shipped artifact (the native CLI and the GOOS=js wasm) via `go list -deps`, and
// fails if a build pulls in any NEW package versus the committed baseline.
//
// It's the supply-chain "a dependency grew a capability" tripwire: a transitive bump that
// suddenly imports net/http, os/exec, runtime/cgo, or pulls the renderer into the wasm shows
// up as an added package — caught with zero prior knowledge of any advisory. It is
// deliberately conservative (source imports, not just linked symbols) and stdlib-only;
// capslock's call-graph analysis is the more precise future upgrade (T-033).
//
// Run:
//
//	go run tools/capgate.go baseline   # (re)write tools/capability.baseline — review the diff in the PR
//	go run tools/capgate.go            # check: non-zero exit on any added package
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
)

const baselineFile = "tools/capability.baseline"

type target struct {
	name string
	env  []string
}

var targets = []target{
	{"cli", nil},
	{"wasm", []string{"GOOS=js", "GOARCH=wasm"}},
}

// excessCapPkgs name network / exec / dynamic-code packages — the ones whose appearance means
// an offline, network-incapable tool has grown a capability. Parse-only siblings (net/url,
// net/netip, net/textproto) are deliberately excluded; they are not capabilities.
var excessCapPkgs = []string{"net", "net/http", "net/rpc", "net/smtp", "crypto/tls", "os/exec", "plugin", "runtime/cgo"}

func hasExcessCaps(p string) bool {
	return slices.Contains(excessCapPkgs, p) || strings.HasPrefix(p, "net/http/")
}

// checkBinary builds the non-stripped CLI and asserts no excess-capability package is actually
// LINKED (post-DCE) — the binary-level companion to the source-level go-list check. nm can't
// read wasm, so the wasm's host-import capability surface is covered separately (T-039).
func checkBinary() (int, error) {
	const tmp = "capgate.nm.exe"
	defer os.Remove(tmp)
	build := exec.Command("go", "build", "-trimpath", "-mod=vendor", "-o", tmp, "./cmd/svgsteg")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("build: %s", strings.TrimSpace(string(out)))
	}
	nm, err := exec.Command("go", "tool", "nm", tmp).Output()
	if err != nil {
		return 0, fmt.Errorf("nm: %w", err)
	}
	syms := string(nm)
	flagged := 0
	for _, p := range excessCapPkgs {
		if strings.Contains(syms, p+".") { // e.g. "net/http." or "os/exec."
			fmt.Printf("  LINKED [cli-binary] %s   <<< CAPABILITY RED FLAG\n", p)
			flagged++
		}
	}
	return flagged, nil
}

func listDeps(env []string) ([]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-mod=vendor", "./cmd/svgsteg")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var pkgs []string
	for l := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			pkgs = append(pkgs, l)
		}
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

func current() (map[string][]string, error) {
	m := map[string][]string{}
	for _, t := range targets {
		p, err := listDeps(t.env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.name, err)
		}
		if len(p) == 0 {
			return nil, fmt.Errorf("%s: empty package list — refusing to pass (go list returned nothing)", t.name)
		}
		m[t.name] = p
	}
	return m, nil
}

func writeBaseline(m map[string][]string) error {
	var b strings.Builder
	b.WriteString("# capability.baseline — transitive package surface per shipped artifact.\n")
	b.WriteString("# Regenerate with: go run tools/capgate.go baseline  (review the diff before committing).\n")
	for _, t := range targets {
		fmt.Fprintf(&b, "[%s]\n", t.name)
		for _, p := range m[t.name] {
			fmt.Fprintln(&b, p)
		}
	}
	return os.WriteFile(baselineFile, []byte(b.String()), 0o644)
}

func readBaseline() (map[string][]string, error) {
	f, err := os.Open(baselineFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string][]string{}
	cur := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			cur = l[1 : len(l)-1]
			continue
		}
		if cur != "" {
			m[cur] = append(m[cur], l)
		}
	}
	return m, sc.Err()
}

func main() {
	mode := "check"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	cur, err := current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capgate: %v\n", err)
		os.Exit(2)
	}

	if mode == "baseline" {
		if err := writeBaseline(cur); err != nil {
			fmt.Fprintf(os.Stderr, "capgate: %v\n", err)
			os.Exit(2)
		}
		n := 0
		for _, t := range targets {
			n += len(cur[t.name])
		}
		fmt.Printf("wrote %s (%d packages across %d artifacts)\n", baselineFile, n, len(targets))
		return
	}

	base, err := readBaseline()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capgate: no baseline (%v); run: go run tools/capgate.go baseline\n", err)
		os.Exit(2)
	}
	added, flagged := 0, 0
	for _, t := range targets {
		have := map[string]bool{}
		for _, p := range base[t.name] {
			have[p] = true
		}
		for _, p := range cur[t.name] {
			if have[p] {
				continue
			}
			added++
			note := ""
			if hasExcessCaps(p) {
				flagged++
				note = "   <<< CAPABILITY RED FLAG"
			}
			fmt.Printf("  ADDED  [%s] %s%s\n", t.name, p, note)
		}
	}
	// binary level: confirm at the linked-symbol level (post-DCE), not only source imports.
	binFlags, err := checkBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capgate: binary check failed: %v\n", err)
		os.Exit(2)
	}
	if added > 0 || binFlags > 0 {
		fmt.Printf("\ncapgate: FAIL — source: %d package(s) added (%d excess-cap); binary: %d excess-cap linked. Review, then re-baseline if intended.\n", added, flagged, binFlags)
		os.Exit(1)
	}
	fmt.Println("capgate: OK — no source-import regression and no excess-cap package linked in the binary")
}
