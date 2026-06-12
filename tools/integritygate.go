//go:build ignore

// integritygate enforces Subresource Integrity on the includes in web/*.html, stratified
// by where the referenced file comes from:
//
//   - STATIC  (committed source, e.g. footer.js, wasm_exec.js): the hash is stable, so the
//     concrete integrity= lives in the committed HTML. `fix` computes/repairs it.
//   - DYNAMIC (build output under out/, e.g. a bundled out/app.js): the hash changes per
//     build, so the committed HTML carries the sentinel integrity="{{integrity}}" and the
//     real hash is filled at publish by `inject`. (Go has text/template, but a sentinel is
//     simpler and doesn't fight HTML.)
//
// SRI-unsupported includes (<img>, <link rel=icon>) are reported, not enforced. The build
// outputs (svgsteg.wasm, parity PNGs) are also hashed into web/out/integrity-manifest.sha384
// for a publish step to verify against — fetch / WebAssembly.instantiateStreaming / <img>
// don't honor tag integrity.
//
// Run:
//
//	go run tools/integritygate.go          # verify  (default; non-zero exit on any gap)
//	go run tools/integritygate.go fix      # fill/repair STATIC integrity in place
//	go run tools/integritygate.go inject    # fill every placeholder with the real hash (publish)
package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	webDir      = "web"
	buildPrefix = "out/" // referenced paths under here are build outputs (dynamic)
	placeholder = "{{integrity}}"
)

func sri(b []byte) string {
	s := sha512.Sum384(b)
	return "sha384-" + base64.StdEncoding.EncodeToString(s[:])
}

var (
	tagRe        = regexp.MustCompile(`(?is)<(?:script|link|img)\b[^>]*>`)
	kindRe       = regexp.MustCompile(`(?is)^<(\w+)`)
	srcRe        = regexp.MustCompile(`(?is)\bsrc\s*=\s*["']([^"']+)["']`)
	hrefRe       = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)
	relRe        = regexp.MustCompile(`(?is)\brel\s*=\s*["']([^"']+)["']`)
	integRe      = regexp.MustCompile(`(?is)\bintegrity\s*=\s*["']([^"']*)["']`)
	stripIntegRe = regexp.MustCompile(`(?is)\s*\bintegrity\s*=\s*["'][^"']*["']`)
)

type finding struct{ file, url, tier, status, detail string }

func attr(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func isLocal(u string) bool {
	l := strings.ToLower(u)
	return u != "" && !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") &&
		!strings.HasPrefix(l, "//") && !strings.HasPrefix(l, "data:") && !strings.HasPrefix(l, "#")
}

func sriSupported(kind, rel string) bool {
	if kind == "script" {
		return true
	}
	if kind == "link" {
		switch strings.ToLower(rel) {
		case "stylesheet", "preload", "modulepreload":
			return true
		}
	}
	return false
}

// setIntegrity strips any existing integrity= and inserts the given hash before the tag close.
func setIntegrity(tag, hash string) string {
	tag = stripIntegRe.ReplaceAllString(tag, "")
	ins := ` integrity="` + hash + `"`
	if body, ok := strings.CutSuffix(tag, "/>"); ok {
		return strings.TrimRight(body, " ") + ins + " />"
	}
	return strings.TrimRight(strings.TrimSuffix(tag, ">"), " ") + ins + ">"
}

func processFile(path, content, mode string) (string, []finding) {
	var fs []finding
	out := tagRe.ReplaceAllStringFunc(content, func(tag string) string {
		kind := strings.ToLower(attr(kindRe, tag))
		url := attr(srcRe, tag)
		if kind == "link" {
			url = attr(hrefRe, tag)
		}
		if !isLocal(url) { // external, data:, fragment — out of scope
			return tag
		}
		if rel := attr(relRe, tag); !sriSupported(kind, rel) {
			where := "<" + kind + ">"
			if rel != "" {
				where = "<" + kind + " rel=" + rel + ">"
			}
			fs = append(fs, finding{path, url, "static", "info", "SRI not supported for " + where})
			return tag
		}
		tier := "static"
		if strings.HasPrefix(url, buildPrefix) {
			tier = "dynamic"
		}
		have := attr(integRe, tag)
		data, ferr := os.ReadFile(filepath.Join(webDir, filepath.FromSlash(url)))
		want := ""
		if ferr == nil {
			want = sri(data)
		}
		// fix fills STATIC includes (commit-time); inject fills every placeholder/stale (publish-time).
		if ferr == nil && have != want && (mode == "inject" || (mode == "fix" && tier == "static")) {
			fs = append(fs, finding{path, url, tier, "filled", want})
			return setIntegrity(tag, want)
		}
		switch {
		case have == placeholder && tier == "dynamic":
			fs = append(fs, finding{path, url, tier, "pending", "placeholder; injected at publish"})
		case have == placeholder:
			fs = append(fs, finding{path, url, tier, "fail", "placeholder on a static include — run `fix`"})
		case ferr != nil:
			fs = append(fs, finding{path, url, tier, "fail", "referenced file not found"})
		case have == want:
			fs = append(fs, finding{path, url, tier, "ok", ""})
		case have == "":
			fs = append(fs, finding{path, url, tier, "fail", "missing integrity (want " + want + ")"})
		default:
			fs = append(fs, finding{path, url, tier, "fail", "stale integrity (want " + want + ")"})
		}
		return tag
	})
	return out, fs
}

// dynamicOutputs hashes the build-generated artifacts into a manifest for publish-time
// verification (tag integrity can't cover a fetch/instantiate).
func dynamicOutputs() []finding {
	var fs []finding
	var manifest []string
	add := func(rel string) (string, bool) {
		data, err := os.ReadFile(filepath.Join(webDir, filepath.FromSlash(rel)))
		if err != nil {
			return "", false
		}
		h := sri(data)
		manifest = append(manifest, h+"  "+rel)
		return h, true
	}
	if h, ok := add("out/svgsteg.wasm"); ok {
		fs = append(fs, finding{"out/svgsteg.wasm", "", "dynamic", "hash", h})
	} else {
		fs = append(fs, finding{"out/svgsteg.wasm", "", "dynamic", "info", "not built; hash deferred to the publish step"})
	}
	pngs, _ := filepath.Glob(filepath.Join(webDir, "out", "parity", "img*", "*.png"))
	sort.Strings(pngs)
	for _, p := range pngs {
		if rel, err := filepath.Rel(webDir, p); err == nil {
			add(filepath.ToSlash(rel))
		}
	}
	if len(pngs) > 0 {
		fs = append(fs, finding{"out/parity PNGs", "", "dynamic", "hash", fmt.Sprintf("%d hashed", len(pngs))})
	}
	if len(manifest) > 0 {
		sort.Strings(manifest)
		man := filepath.Join(webDir, "out", "integrity-manifest.sha384")
		if err := os.WriteFile(man, []byte(strings.Join(manifest, "\n")+"\n"), 0o644); err == nil {
			fs = append(fs, finding{filepath.ToSlash(filepath.Join("out", "integrity-manifest.sha384")), "", "dynamic", "hash", fmt.Sprintf("manifest written (%d entries)", len(manifest))})
		}
	}
	return fs
}

func main() {
	mode := "verify"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if mode != "verify" && mode != "fix" && mode != "inject" {
		fmt.Fprintln(os.Stderr, "usage: go run tools/integritygate.go [verify|fix|inject]")
		os.Exit(2)
	}

	htmls, _ := filepath.Glob(filepath.Join(webDir, "*.html"))
	sort.Strings(htmls)
	var all []finding
	for _, h := range htmls {
		content, err := os.ReadFile(h)
		if err != nil {
			all = append(all, finding{h, "", "static", "fail", "read: " + err.Error()})
			continue
		}
		nc, fs := processFile(h, string(content), mode)
		all = append(all, fs...)
		if (mode == "fix" || mode == "inject") && nc != string(content) {
			if err := os.WriteFile(h, []byte(nc), 0o644); err != nil {
				all = append(all, finding{h, "", "static", "fail", "write: " + err.Error()})
			}
		}
	}
	all = append(all, dynamicOutputs()...)

	order := map[string]int{"ok": 0, "filled": 1, "pending": 2, "hash": 3, "info": 4, "fail": 5}
	label := map[string]string{"ok": "OK     ", "filled": "FILLED ", "pending": "PENDING", "hash": "hash   ", "info": "info   ", "fail": "FAIL   "}
	fails := 0
	for _, tier := range []string{"static", "dynamic"} {
		var rows []finding
		for _, f := range all {
			if f.tier == tier {
				rows = append(rows, f)
			}
		}
		if len(rows) == 0 {
			continue
		}
		sort.SliceStable(rows, func(i, j int) bool { return order[rows[i].status] < order[rows[j].status] })
		fmt.Printf("%s:\n", strings.ToUpper(tier))
		for _, f := range rows {
			if f.status == "fail" {
				fails++
			}
			loc := f.file
			if f.url != "" {
				loc += " -> " + f.url
			}
			line := "  " + label[f.status] + " " + loc
			if f.detail != "" {
				line += "   " + f.detail
			}
			fmt.Println(line)
		}
	}
	fmt.Printf("\nintegritygate (%s): %d checks, %d fail(s)\n", mode, len(all), fails)
	if mode == "verify" && fails > 0 {
		os.Exit(1)
	}
}
