//go:build ignore

// verify_oksvg_provenance.go — chain-of-custody check for third_party/oksvg (BACKLOG T-045).
//
// Proves third_party/oksvg is the authentic upstream module github.com/fyne-io/oksvg@<VERSION>,
// byte-for-byte, EXCEPT exactly the files we intentionally MODIFIED (allowedPatches) and ADDED
// (allowedAdditions). Any other difference => tampering => exit 1. For each patched file it
// prints the upstream hash and our patched hash, so the patch is provably "atop" a known input.
//
// Trust anchor: `go mod download` verifies the upstream bytes against sum.golang.org (the public
// transparency log) before we compare. The filesystem `replace` bypasses `go mod verify`, so this
// tool stands in for it (the same compensating control as verify_brotli_provenance.go).
//
// Run:  go run tools/verify_oksvg_provenance.go
// Zero third-party imports (stdlib only). DEV TOOLING; never compiled into svgsteg.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	module  = "github.com/fyne-io/oksvg"
	version = "v0.2.0"
	local   = "third_party/oksvg"
)

// Files we intentionally MODIFIED vs upstream (the patch). A byte-diff here is expected.
var allowedPatches = map[string]bool{
	"svg_path.go": true,
}

// Files we ADDED that are not part of upstream.
var allowedAdditions = map[string]bool{
	"PATCH-NOTES.md": true,
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashTree returns relpath -> sha256 for every regular file under root.
func hashTree(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)], err = sha256File(p)
		return err
	})
	return out, err
}

func main() {
	fmt.Printf("== verifying %s == upstream %s@%s (patched: %v, added: %v) ==\n\n",
		local, module, version, keys(allowedPatches), keys(allowedAdditions))

	fmt.Println("[1/4] go mod download (anchors upstream bytes to sum.golang.org)")
	dl := exec.Command("go", "mod", "download", "-x", module+"@"+version)
	dl.Stderr = os.Stderr
	if err := dl.Run(); err != nil {
		fail("go mod download failed: %v", err)
	}
	gomodcache, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		fail("go env GOMODCACHE failed: %v", err)
	}
	upstream := filepath.Join(strings.TrimSpace(string(gomodcache)), filepath.FromSlash(module+"@"+version))
	if _, err := os.Stat(upstream); err != nil {
		fail("verified upstream not found at %s: %v", upstream, err)
	}

	fmt.Printf("[2/4] hashing upstream: %s\n", upstream)
	up, err := hashTree(upstream)
	if err != nil {
		fail("hash upstream: %v", err)
	}
	fmt.Printf("[3/4] hashing local:    %s\n", local)
	lo, err := hashTree(local)
	if err != nil {
		fail("hash local: %v", err)
	}

	fmt.Print("[4/4] comparing...\n\n")
	var (
		matched  int
		patched  []string
		mismatch []string // byte-differ, NOT an allowed patch => tampering
		missing  []string // in upstream, absent locally
		extra    []string // local-only, NOT an allowed addition
	)
	for rel, upSum := range up {
		switch loSum, ok := lo[rel]; {
		case !ok:
			missing = append(missing, rel)
		case loSum == upSum:
			matched++
		case allowedPatches[rel]:
			patched = append(patched, rel)
			fmt.Printf("  PATCH %s\n        upstream %s\n        patched  %s\n", rel, upSum, loSum)
		default:
			mismatch = append(mismatch, rel)
		}
	}
	for rel := range lo {
		if _, inUp := up[rel]; !inUp && !allowedAdditions[rel] {
			extra = append(extra, rel)
		}
	}

	// every allowed patch must actually be present AND differing (else the patch silently didn't apply)
	var notApplied []string
	for f := range allowedPatches {
		applied := false
		for _, p := range patched {
			if p == f {
				applied = true
			}
		}
		if !applied {
			notApplied = append(notApplied, f)
		}
	}

	sort.Strings(mismatch)
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(patched)
	sort.Strings(notApplied)
	fmt.Printf("\n  byte-identical : %d\n  patched (allowed): %v\n", matched, patched)

	if len(mismatch)+len(missing)+len(extra)+len(notApplied) == 0 {
		fmt.Printf("\nPASS: %s == upstream %s@%s byte-for-byte, except documented patch %v + addition %v.\n",
			local, module, version, keys(allowedPatches), keys(allowedAdditions))
		fmt.Println("Chain of custody intact (anchored to sum.golang.org).")
		return
	}

	fmt.Println("\n*** FAIL: tree is NOT 'upstream + only the documented patch' ***")
	if len(mismatch) > 0 {
		fmt.Printf("  UNDOCUMENTED modifications: %v\n", mismatch)
	}
	if len(missing) > 0 {
		fmt.Printf("  unexpected removals: %v\n", missing)
	}
	if len(extra) > 0 {
		fmt.Printf("  unexpected additions: %v\n", extra)
	}
	if len(notApplied) > 0 {
		fmt.Printf("  expected-patched but byte-identical to upstream (patch not applied?): %v\n", notApplied)
	}
	os.Exit(1)
}

func keys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(2)
}
