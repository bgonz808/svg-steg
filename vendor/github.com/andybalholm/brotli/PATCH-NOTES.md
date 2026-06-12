# third_party/brotli — provenance & patch record

This directory is a **local, minimally-patched copy** of an upstream Go module,
wired in via a `replace` directive in the root `go.mod`. It exists so the network
strip is **durable across `go mod vendor`** (which would otherwise regenerate the
upstream `http.go` and re-link `net/http`).

## Upstream identity (verified)

- Module: `github.com/andybalholm/brotli`
- Version: `v1.2.1`
- Verified hashes (from `go.sum`, recorded at admission against `sum.golang.org`):
  - zip:    `h1:R+f5xP285VArJDRgowrfb9DqL18yVK0gKAW/F+eTWro=`
  - go.mod: `h1:rzTDkvFWvIrjDXZHkuS16NPggd91W3kUSvPlQ1pLaKY=`
- Source of copy: local module cache `GOPATH/pkg/mod/github.com/andybalholm/brotli@v1.2.1`
  (populated by `go mod download`, which verified the above hashes).

## The patch — exactly one change

- **Removed `http.go`** — the only file importing `net/http`. It provided
  `HTTPCompressor` / `HTTPCompressorWithLevel` / `negotiateContentEncoding` / `parseAccept`,
  HTTP-response-compression helpers that **svgsteg never calls**. Importing `net/http`
  forces `net/http.init()` → `DefaultTransport` → `net.Dialer` → the socket stack into the
  binary, even though the helper is unused. Removing the file eliminates `net/http`, `net`,
  and `crypto/tls` from the build (55 → 0 net symbols).

Nothing else is modified. `git diff` against the upstream source (or re-downloading
v1.2.1 and diffing) shows the **single deletion** and no other change. The remaining
`*_test.go` files are inert: this is a separate module (own `go.mod`), so the root
module's `go test ./...` does not descend into it, and `go mod vendor` excludes test files.

## Re-verification (chain of custody)

Run the committed zero-dependency verifier. It downloads pristine upstream (Go
verifies the bytes against sum.golang.org), then SHA-256-compares every file
against this copy and asserts the ONLY difference is the removal of `http.go`:

    go run tools/verify_brotli_provenance.go

Expected: `PASS ... byte-for-byte, minus exactly [http.go]`. The verifier exits
non-zero (printing MODIFIED / ADDED / UNDOCUMENTED-REMOVED files) on any other
drift, so it doubles as a CI gate. Last run: **92 files byte-identical, http.go
removed**, chain of custody intact.

## Why `replace` instead of editing `vendor/`

Editing `vendor/` is silently reverted by the next `go mod vendor`. A `replace` to this
copy makes the stripped source the *thing that gets vendored*, so plain `go build` and
`go mod vendor` stay net-free permanently. Backstop: the `nm` symbol-invariant CI gate
(see BACKLOG T-005) fails the build if any `net.*` symbol reappears.

## Retirement condition (when this fork can be dropped)

This fork exists **only** because upstream ships `http.go` and thus links `net/http`. If upstream
ever **removes `http.go`, gates it behind a build tag, or splits it into a separate module**, the
fork's reason disappears: drop the `replace`, delete this directory and `tools/verify_brotli_provenance.go`,
`go get github.com/andybalholm/brotli` wholesale (restoring `sum.golang.org` coverage), and confirm the
`releasegate.go` nm invariant still shows `net = 0`. Tracked as **BACKLOG T-034** (external trigger).
