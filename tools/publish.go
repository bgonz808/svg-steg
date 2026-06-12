//go:build ignore

// publish.go — the single source of truth for build/publish, run identically locally and by
// CI (CI is a thin wrapper: checkout -> setup-go -> go run tools/publish.go). Reproducible
// builds (-trimpath + vendored deps + a pinned toolchain) make the local artifact hashes
// match CI's, which is what lets us hash our own outputs and trust the result anywhere.
//
// Steps: build wasm -> render parity (patched + upstream) -> integrity verify (+ manifest) ->
// assemble dist/ -> inject the wasm SHA-384 into the dist HTML (tag integrity can't cover
// WebAssembly.instantiateStreaming, so the loader verifies the bytes at runtime instead).
//
// Run:
//
//	go run tools/publish.go            # produce ./dist
//	go run tools/publish.go --serve    # produce ./dist and preview the exact published bytes on :8820
package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	webDir          = "web"
	distDir         = "dist"
	wasmRel         = "out/svgsteg.wasm"
	wasmPlaceholder = "{{wasm-integrity}}"
	serveAddr       = "127.0.0.1:8820"
)

// staticFiles is the committed web/ payload, listed explicitly so build scratch never leaks into dist.
var staticFiles = []string{"index.html", "parity.html", "footer.js", "wasm_exec.js", "favicon.svg", ".nojekyll"}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "publish FAILED: "+format+"\n", a...)
	os.Exit(1)
}

func sh(args ...string) { shEnv(nil, args...) }

func shEnv(env []string, args ...string) {
	fmt.Printf("  $ %s\n", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("%s: %v", args[0], err)
	}
}

func sri(b []byte) string {
	s := sha512.Sum384(b)
	return "sha384-" + base64.StdEncoding.EncodeToString(s[:])
}

func copyFile(src, dst string) {
	b, err := os.ReadFile(src)
	if err != nil {
		fatal("read %s: %v", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		fatal("mkdir %s: %v", filepath.Dir(dst), err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		fatal("write %s: %v", dst, err)
	}
}

func copyDir(src, dst string) {
	if err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		copyFile(p, target)
		return nil
	}); err != nil {
		fatal("copy %s: %v", src, err)
	}
}

func main() {
	serve := false
	for _, a := range os.Args[1:] {
		if a == "--serve" {
			serve = true
		}
	}

	fmt.Println("== publish (build SSOT) ==")

	// 1) build wasm (deterministic: -trimpath + vendored deps -> hash matches CI)
	fmt.Println("[1/5] build wasm")
	shEnv(append(os.Environ(), "GOOS=js", "GOARCH=wasm"),
		"go", "build", "-trimpath", "-mod=vendor", "-o", filepath.Join(webDir, wasmRel), "./cmd/svgsteg")

	// 2) render parity: patched (vendored) + pristine upstream (go.upstream.mod)
	fmt.Println("[2/5] render parity (patched + upstream)")
	sh("go", "run", "tools/renderparity.go")
	sh("go", "run", "-mod=mod", "-modfile=go.upstream.mod", "tools/renderparity.go", "--variant", "upstream")

	// 3) integrity gate: static SRI must be correct; also refreshes the output hash manifest
	fmt.Println("[3/5] integrity verify")
	sh("go", "run", "tools/integritygate.go", "verify")

	// 4) assemble dist/ from the committed static payload + the build outputs
	fmt.Println("[4/5] assemble dist/")
	if err := os.RemoveAll(distDir); err != nil {
		fatal("clean dist: %v", err)
	}
	for _, f := range staticFiles {
		copyFile(filepath.Join(webDir, f), filepath.Join(distDir, f))
	}
	copyDir(filepath.Join(webDir, "out"), filepath.Join(distDir, "out"))

	// 5) inject the wasm SHA-384 into dist HTML (runtime verification substitutes for tag integrity)
	fmt.Println("[5/5] inject wasm integrity")
	wasmBytes, err := os.ReadFile(filepath.Join(distDir, wasmRel))
	if err != nil {
		fatal("read dist wasm: %v", err)
	}
	hash := sri(wasmBytes)
	for _, f := range []string{"index.html", "parity.html"} {
		p := filepath.Join(distDir, f)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if !strings.Contains(string(b), wasmPlaceholder) {
			fmt.Printf("  WARN: %s has no %s placeholder (loader not wired for runtime verification)\n", f, wasmPlaceholder)
		}
		out := strings.ReplaceAll(string(b), wasmPlaceholder, hash)
		if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
			fatal("write %s: %v", p, err)
		}
	}
	fmt.Printf("  wasm %s -> %s\n", wasmRel, hash)

	fmt.Printf("\n== dist/ ready (publish from here) ==\n")

	if serve {
		fmt.Printf("serving the exact published bytes at http://%s  (Ctrl-C to stop)\n", serveAddr)
		if err := http.ListenAndServe(serveAddr, http.FileServer(http.Dir(distDir))); err != nil {
			fatal("serve: %v", err)
		}
	}
}
