//go:build ignore

// pingate — fail-closed gate: every `uses:` in .github/workflows/** must pin the action to a
// full 40-hex commit SHA, never a tag/branch/placeholder. A moved tag (tj-actions 2025,
// Trivy-Aqua 2026) cannot change a pinned SHA, so this is the tripwire that catches an
// unpinned reference the moment it lands — the check that would have flagged the REPLACE_SHA
// placeholders automatically. Local actions (`uses: ./...`) are path-based and exempt.
// Stdlib-only dev tooling; never compiled into the shipped binary.
//
// Run:  go run tools/pingate.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const wfDir = ".github/workflows"

var (
	reUses = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*(\S+)`)
	reSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func main() {
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pingate: cannot read %s: %v (a gate wired into CI must find the workflows it guards)\n", wfDir, err)
		os.Exit(2)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			files = append(files, filepath.Join(wfDir, n))
		}
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "pingate: no workflow files in %s — refusing to pass (nothing to guard is unexpected)\n", wfDir)
		os.Exit(2)
	}

	unpinned, checked := 0, 0
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pingate: %v\n", err)
			os.Exit(2)
		}
		sc := bufio.NewScanner(fh)
		ln := 0
		for sc.Scan() {
			ln++
			m := reUses.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			ref := strings.Trim(m[1], `"'`)
			if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, ".\\") {
				continue // local action / same-repo reusable workflow — no pin to check
			}
			checked++
			at := strings.LastIndex(ref, "@")
			if at < 0 {
				unpinned++
				fmt.Printf("  UNPINNED %s:%d  uses: %s   (no @SHA)\n", f, ln, ref)
				continue
			}
			if sha := ref[at+1:]; !reSHA.MatchString(sha) {
				unpinned++
				fmt.Printf("  UNPINNED %s:%d  uses: %s   (ref %q is not a 40-hex SHA)\n", f, ln, ref, sha)
			}
		}
		if cerr := sc.Err(); cerr != nil {
			fh.Close()
			fmt.Fprintf(os.Stderr, "pingate: read %s: %v\n", f, cerr)
			os.Exit(2)
		}
		fh.Close()
	}

	if unpinned > 0 {
		fmt.Printf("\npingate: FAIL — %d of %d `uses:` not pinned to a 40-hex commit SHA (across %d workflow file(s))\n", unpinned, checked, len(files))
		os.Exit(1)
	}
	fmt.Printf("pingate: OK — all %d `uses:` across %d workflow file(s) pinned to 40-hex commit SHAs\n", checked, len(files))
}
