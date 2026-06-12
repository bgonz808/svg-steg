# Capability decisions

Durable log for the capability-decision ritual (`SUPPLY_CHAIN.md` §3). When the `capslock`
capability diff flags a new high-risk capability on a dependency (network / exec / unsafe-pointer /
file), the change is investigated, decided, and **recorded here before merge**. Append-only — never
rewrite a closed entry; supersede it with a new dated one.

Pre-audit entries are date-precise; from the 2026-06-09 audit forward, new entries record to the
second (`date`-sourced), per the BACKLOG dating policy. The machine baseline the diff compares against
is `.capslock-baseline.json` (generated at T-033 adoption).

## Entry schema

    <module> @ <version>
      date:        YYYY-MM-DD[ HH:MM:SS TZ]
      capability:  the capability + its call path (from `capslock -output=v`)
      source:      file/function that acquires it
      decision:    accept | vendor-and-strip | reject | hold-old
      proof:       byte-identity / nm invariant / attestation reference
      rationale:   why

---

## github.com/andybalholm/brotli @ v1.2.1
- **date:** 2026-06-09
- **capability:** network — via `net/http`
- **source:** `http.go` (brotli's HTTP content-encoding helpers; never reached by the encoder). Found via
  `go list -deps` + `go tool nm` (pre-`capslock`); this is the worked example the ritual generalizes.
- **decision:** **vendor-and-strip** — `replace github.com/andybalholm/brotli => ./third_party/brotli`, `http.go` removed.
- **proof:** `tools/verify_brotli_provenance.go` — 92 files byte-identical to upstream `v1.2.1`, only `http.go`
  removed (anchored to `sum.golang.org`); `tools/releasegate.go` nm invariant asserts `net.* = 0` in the binary.
- **rationale:** the only network-capability path in the tree; svgsteg is offline / network-incapable, so
  `net = 0` is a hard requirement. Stripping a leaf-only HTTP helper is behavior-neutral for the codec.
- **revisit:** if upstream drops the net linkage, retire the fork and use the module wholesale — T-034
  / `third_party/brotli/PATCH-NOTES.md`.

---

## Renderer stack — srwiley/oksvg, srwiley/rasterx, golang.org/x/{image,text,net}
- **date:** 2026-06-09
- **capability (measured so far):** **no** network / exec — *proven*. (`x/net` here is the `html/charset`
  decoder — charset tables, not sockets.) Full capslock enumeration is captured as the baseline at T-033.
- **source:** SVG rasterization for the visual-fidelity axis (in-memory, offline).
- **decision:** **accept** — pure-Go decode/render; no exfil surface.
- **proof:** `releasegate.go` nm invariant — `net.*` / `net/http.*` / `crypto/tls.*` / `os/exec.* = 0`;
  built `CGO_ENABLED=0`.
- **rationale:** rendering is required to measure visual fidelity; the critical capabilities (network, exec)
  are proven absent and guarded every release by the nm invariant. The first `capslock` run (T-033) records
  the complete capability set as `.capslock-baseline.json`; any future bump that adds network/exec/unsafe gets
  a new entry here.
