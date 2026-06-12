//go:build ignore

// verify_action_pin — resolve + verify SHA pins for GitHub Actions (dev-only helper).
//
// Modes:
//
//	go run tools/verify_action_pin.go resolve <owner/repo[:tag]>...
//	    No :tag => latest release. Resolves + verifies a tag and prints a paste-ready
//	    `repo@<sha> # <tag>` PIN LINE. Use when first pinning or adopting an action.
//	go run tools/verify_action_pin.go check [workflow.yml...]
//	    For every `uses: repo@<sha> # vTag`, re-resolve vTag two independent ways and assert it
//	    still equals the pinned <sha>. Reports signature + age; nonzero on drift or error.
//	    Defaults to .github/workflows/*.yml — the Renovate-PR drift guard.
//
// Each pin clears four gates (SUPPLY_CHAIN.md §11): two-protocol tag->SHA agreement, signature,
// age >= 48h, and a `# vX.Y.Z` comment. tools/pingate.go enforces the offline invariant (every
// `uses:` is a 40-hex SHA); this adds the ONLINE checks it cannot make. Zero-dependency: it drives
// the `gh` and `git` CLIs via os/exec (as the other tools drive `go`), so nothing is vendored.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	minAgeH = 48
	retries = 3
)

var (
	reUses = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*(\S+)`)
	reTag  = regexp.MustCompile(`#\s*(v?[0-9][0-9A-Za-z._-]*)`)
	reSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func runOut(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// resolveSHA returns (sha, 0) on two-protocol agreement; ("", 2) unresolved (network/API, not
// tamper); ("", 3) a PERSISTENT two-protocol disagreement (real mismatch — moved tag). Because a
// disagreement is the serious "tamper" signal, it is never reported on a single read: a lone
// disagreement is re-confirmed, and a flake that won't reproduce is downgraded to unresolved.
func resolveSHA(repo, tag string) (string, int) {
	sha, st := resolveOnce(repo, tag)
	if st != 3 {
		return sha, st
	}
	switch sha2, st2 := resolveOnce(repo, tag); st2 {
	case 0:
		return sha2, 0 // first read was the flake; tags actually agree
	case 3:
		return "", 3 // disagreement reproduced — real
	default:
		return "", 2 // couldn't confirm — do not cry tamper on one read
	}
}

func resolveOnce(repo, tag string) (string, int) {
	var s1, s2 string
	for i := 0; i < retries && s1 == ""; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		s1 = runOut("gh", "api", "repos/"+repo+"/commits/"+tag, "--jq", ".sha")
	}
	for i := 0; i < retries && s2 == ""; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		s2 = firstField(runOut("git", "ls-remote", "https://github.com/"+repo, "refs/tags/"+tag+"^{}"))
		if s2 == "" {
			s2 = firstField(runOut("git", "ls-remote", "https://github.com/"+repo, "refs/tags/"+tag))
		}
	}
	if s1 == "" || s2 == "" {
		return "", 2
	}
	if s1 == s2 {
		return s1, 0
	}
	return "", 3
}

// commitMeta returns verified, reason, ageHours for a commit (one gh call; age -1 if unparsable).
func commitMeta(repo, sha string) (string, string, int) {
	tsv := runOut("gh", "api", "repos/"+repo+"/commits/"+sha, "--jq",
		`[(.commit.verification.verified|tostring), .commit.verification.reason, .commit.committer.date]|@tsv`)
	parts := strings.Split(tsv, "\t")
	for len(parts) < 3 {
		parts = append(parts, "?")
	}
	age := -1
	if t, err := time.Parse(time.RFC3339, parts[2]); err == nil {
		age = int(time.Since(t).Hours())
	}
	return parts[0], parts[1], age
}

func repoOf(refPath string) string { // first two path segments of owner/repo[/sub...]
	if p := strings.Split(refPath, "/"); len(p) >= 2 {
		return p[0] + "/" + p[1]
	}
	return refPath
}

func orNone(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

func resolveMode(specs []string) int {
	rc := 0
	for _, spec := range specs {
		repo, tag := spec, ""
		if r, t, ok := strings.Cut(spec, ":"); ok {
			repo, tag = r, t
		}
		if tag == "" {
			tag = runOut("gh", "api", "repos/"+repo+"/releases/latest", "--jq", ".tag_name")
		}
		fmt.Printf("\n=== %s @ %s ===\n", repo, orNone(tag))
		if tag == "" || tag == "null" {
			fmt.Println("  !! no tag resolved")
			rc = 1
			continue
		}
		sha, st := resolveSHA(repo, tag)
		switch st {
		case 2:
			fmt.Printf("  !! UNRESOLVED after %d retries (network/API) — re-run\n", retries)
			rc = 1
			continue
		case 3:
			fmt.Println("  !! two-protocol MISMATCH — DO NOT PIN, investigate")
			rc = 1
			continue
		}
		v, r, age := commitMeta(repo, sha)
		ageOK := "yes"
		if age < minAgeH {
			ageOK = "NO"
			rc = 1
		}
		fmt.Printf("  two-protocol : agree (%s)\n", sha)
		fmt.Printf("  signature    : verified=%s (%s)\n", v, r)
		fmt.Printf("  age          : %dh (>=%dh=%s)\n", age, minAgeH, ageOK)
		fmt.Printf("  PIN LINE     : %s@%s # %s\n", repo, sha, tag)
	}
	return rc
}

func checkMode(files []string) int {
	if len(files) == 0 {
		files, _ = filepath.Glob(".github/workflows/*.yml")
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "verify_action_pin: no workflow files to check")
		return 2
	}
	drift, errs, checked, skipped := 0, 0, 0, 0
	type res struct {
		sha string
		st  int
	}
	memo := map[string]res{} // resolve each (repo,tag) once per run — fewer calls, less API pressure
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  !! %v\n", err)
			errs++
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			m := reUses.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ref := strings.Trim(m[1], `"'`)
			if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, `.\`) {
				continue
			}
			at := strings.LastIndex(ref, "@")
			if at < 0 {
				continue
			}
			sha := ref[at+1:]
			if !reSHA.MatchString(sha) {
				continue // non-SHA is pingate's job
			}
			repo := repoOf(ref[:at])
			tag := ""
			if tm := reTag.FindStringSubmatch(line); tm != nil {
				tag = tm[1]
			}
			if tag == "" {
				fmt.Printf("  SKIP  %s@%s  (no # vTag comment — can't drift-check)\n", repo, sha[:12])
				skipped++
				continue
			}
			checked++
			key := repo + "@" + tag
			r, ok := memo[key]
			if !ok {
				s, st := resolveSHA(repo, tag)
				r = res{s, st}
				memo[key] = r
			}
			want, st := r.sha, r.st
			switch {
			case st == 0 && want == sha:
				v, _, age := commitMeta(repo, sha)
				fmt.Printf("  OK    %s @ %s -> %s  (verified=%s, %dh)\n", repo, tag, sha[:12], v, age)
			case st == 2:
				fmt.Printf("  ERROR %s @ %s : UNRESOLVED after %d retries (network/API, not tamper) — re-run\n", repo, tag, retries)
				errs++
			default:
				disp := "<protocols disagree>"
				if want != "" {
					disp = want[:12]
				}
				fmt.Printf("  DRIFT %s @ %s : pinned %s but tag resolves to %s  <<< INVESTIGATE (possible moved tag)\n", repo, tag, sha[:12], disp)
				drift++
			}
		}
	}
	fmt.Println()
	if drift > 0 || errs > 0 {
		fmt.Printf("verify_action_pin: FAIL — drift=%d error=%d across %d checked (%d skipped)\n", drift, errs, checked, skipped)
		return 1
	}
	fmt.Printf("verify_action_pin: OK — %d pin(s) match their tag (%d skipped, no comment)\n", checked, skipped)
	return 0
}

func main() {
	args := os.Args[1:]
	mode := "check"
	if len(args) > 0 {
		mode, args = args[0], args[1:]
	}
	switch mode {
	case "resolve":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: verify_action_pin.go resolve <owner/repo[:tag]>...")
			os.Exit(2)
		}
		os.Exit(resolveMode(args))
	case "check":
		os.Exit(checkMode(args))
	default:
		fmt.Fprintln(os.Stderr, "usage: verify_action_pin.go {resolve <owner/repo[:tag]>... | check [workflow.yml...]}")
		os.Exit(2)
	}
}
