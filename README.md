# svgsteg

Offline steganography that hides a payload in the **least-significant decimals of SVG path
coordinates** — the digits a vector editor would plausibly have emitted anyway. The aim is to stay
**practically invisible on the three axes a reviewer checks: as XML, as numbers, and as rendered.**
One Go codebase, two front ends: a CLI and a Go→WebAssembly web UI that runs entirely in the browser.

> Research prototype. It targets those three plausibility axes, not provable undetectability — in
> particular it makes no claim against statistical steganalysis of coordinate-LSB distributions.

## How it works

SVG paths are full of decimal coordinates (`M 12.34 56.789 …`). svgsteg picks coordinates whose
precision is high enough to carry bits without standing out — guided by a per-canvas precision
floor and a numeric-style detector — and writes the payload into their trailing decimals (the
LSBs). A carrier is consumed only if it survives a round-trip decode, so recovery is byte-exact.
By default the payload is compressed, encrypted (key derived via PBKDF2-HMAC-SHA256), and wrapped
in a SHA-256 integrity frame before it is spread across the eligible coordinates. Because it only
touches sub-pixel precision, the result renders identically. `capacity` scores how much a given SVG
can hold and how plausible the result stays on each axis — numeric style, XML structure, rendered pixels.

## Build

```
go build -o svgsteg ./cmd/svgsteg
```

Standard-library core; the compression and SVG-rendering dependencies are vendored and `go.sum`
hash-locked, so it builds and runs **offline** — the binary links zero `net`/`os-exec` symbols
(enforced by a capability gate in CI).

## Use

```
# embed
svgsteg encode --in logo.svg --payload secret.bin --out logo.steg.svg --passphrase-file pass.txt
svgsteg encode --in logo.svg --payload-text "hello" --out logo.steg.svg --no-encrypt

# recover
svgsteg decode --in logo.steg.svg --out recovered.bin --passphrase-file pass.txt

# inspect carrier capacity + numeric style
svgsteg capacity --in logo.svg --histogram --map

# render and compare two SVGs
svgsteg diff --a logo.svg --b logo.steg.svg --diff-out diff.png
```

`svgsteg <command> --help` for the full flags (compression modes, carrier-policy knobs, KDF iterations).

## Web

A WebAssembly build runs the encoder client-side — no upload, no server.
**Live: <https://bgonz808.github.io/svg-steg/>** (deployed from `main` via `pages.yml`).

## Project

- **Supply chain:** reproducible builds, vendored + hash-locked deps, SHA-pinned Actions, CI gates
  (capability / integrity / workflow-pin). Runbook: `docs/SUPPLY_CHAIN.md`.
- **Roadmap:** `BACKLOG.md`.
- **License:** see [LICENSE](LICENSE).
