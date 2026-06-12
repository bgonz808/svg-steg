//go:build ignore

// verify_brotli_provenance.go — chain-of-custody check for third_party/brotli.
//
// Proves that third_party/brotli is the authentic upstream module
// github.com/andybalholm/brotli@<VERSION>, byte-for-byte, MINUS exactly the
// files listed in allowedRemovals (http.go), plus only our own documented
// additions (PATCH-NOTES.md). Any other difference => tampering => exit 1.
//
// Trust anchor: `go mod download` verifies the upstream bytes against
// sum.golang.org (the public transparency log) before we compare. The replace
// directive bypasses `go mod verify`, so this tool stands in for it.
//
// Run:  go run tools/verify_brotli_provenance.go
// Zero third-party imports (stdlib only). Uses os/exec to drive the go toolchain;
// this is DEV TOOLING and is never compiled into svgsteg.exe.

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
	module  = "github.com/andybalholm/brotli"
	version = "v1.2.1"
	local   = "third_party/brotli"
)

// Files deliberately removed from the upstream copy (the entire "patch").
var allowedRemovals = map[string]bool{
	"http.go": true,
}

// Files we added that are not part of upstream (must be clearly ours).
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
		rel = filepath.ToSlash(rel)
		sum, err := sha256File(p)
		if err != nil {
			return err
		}
		out[rel] = sum
		return nil
	})
	return out, err
}

func main() {
	// 1) Anchor: ensure the authentic upstream is present + verified vs sum.golang.org.
	fmt.Printf("== verifying %s == upstream %s@%s (minus %v) ==\n\n",
		local, module, version, keys(allowedRemovals))
	fmt.Println("[1/4] go mod download (verifies upstream bytes against sum.golang.org)")
	dl := exec.Command("go", "mod", "download", "-x", module+"@"+version)
	dl.Stderr = os.Stderr
	if err := dl.Run(); err != nil {
		fail("go mod download failed: %v", err)
	}

	gomodcache, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		fail("go env GOMODCACHE failed: %v", err)
	}
	upstream := filepath.Join(strings.TrimSpace(string(gomodcache)),
		filepath.FromSlash(module+"@"+version))
	if _, err := os.Stat(upstream); err != nil {
		fail("verified upstream not found at %s: %v", upstream, err)
	}

	// 2) Hash both trees.
	fmt.Printf("[2/4] hashing upstream tree: %s\n", upstream)
	up, err := hashTree(upstream)
	if err != nil {
		fail("hash upstream: %v", err)
	}
	fmt.Printf("[3/4] hashing local copy:    %s\n", local)
	lo, err := hashTree(local)
	if err != nil {
		fail("hash local: %v", err)
	}

	// 3) Compare, classifying every file.
	fmt.Println("[4/4] comparing...\n")
	var (
		matched   int
		removed   []string
		mismatch  []string
		missing   []string // in upstream, absent locally, NOT an allowed removal
		extra     []string // local-only, NOT an allowed addition
	)
	for rel, upSum := range up {
		loSum, ok := lo[rel]
		switch {
		case !ok && allowedRemovals[rel]:
			removed = append(removed, rel)
		case !ok:
			missing = append(missing, rel)
		case loSum == upSum:
			matched++
		default:
			mismatch = append(mismatch, rel)
		}
	}
	for rel := range lo {
		if _, inUp := up[rel]; !inUp && !allowedAdditions[rel] {
			extra = append(extra, rel)
		}
	}

	// 4) Verdict.
	sort.Strings(mismatch)
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(removed)

	fmt.Printf("  byte-identical files : %d\n", matched)
	fmt.Printf("  removed (allowed)    : %v\n", removed)
	if len(mismatch)+len(missing)+len(extra) == 0 &&
		len(removed) == len(allowedRemovals) {
		fmt.Printf("\nPASS: %s is upstream %s@%s byte-for-byte, minus exactly %v.\n",
			local, module, version, keys(allowedRemovals))
		fmt.Println("Chain of custody intact (anchored to sum.golang.org).")
		return
	}

	fmt.Println("\n*** FAIL: tree does NOT match 'upstream minus the documented patch' ***")
	if len(mismatch) > 0 {
		fmt.Printf("  MODIFIED files (byte-differ from upstream!): %v\n", mismatch)
	}
	if len(extra) > 0 {
		fmt.Printf("  UNEXPECTED added files: %v\n", extra)
	}
	if len(missing) > 0 {
		fmt.Printf("  UNDOCUMENTED removals: %v\n", missing)
	}
	notRemoved := []string{}
	for f := range allowedRemovals {
		found := false
		for _, r := range removed {
			if r == f {
				found = true
			}
		}
		if !found {
			notRemoved = append(notRemoved, f)
		}
	}
	if len(notRemoved) > 0 {
		fmt.Printf("  expected-removed but still present: %v\n", notRemoved)
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
