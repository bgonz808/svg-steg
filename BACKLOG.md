# svgsteg — Backlog

Each item is a ticket; priority is relative. Linkages are authored once per ticket via a `Links:` line
using canonical verbs (`blocked-by`, `composes`, `spawned-by`, `supersedes`, `informed-by`, `related`);
inverse edges and the graph view are derived by `tools/backlog_graph.go` (`go run tools/backlog_graph.go`
to regenerate — never hand-edit the generated block).

---

## Phase 1 — hardening (DONE)

- **T-001 — Zero-dep release self-check** — *core DONE 2026-06-09 (via T-005); remainder DEFERRED.*
  Core invariants in `tools/releasegate.go`. Remainder: string-IOC scan, entropy scan, SBOM emit, optional Defender pass.
  Links: blocked-by=T-002,T-003,T-004
- **T-002 — Delete dead `builtin-simple` helpers** — *DONE 2026-06-09.*
  11 funcs + struct removed; kept `renderSVGBuiltinOKSVG` + `parseViewBox`. svgsteg.go 3673→3290. nm net/exec still 0.
- **T-003 — Durable brotli strip (`replace`→`third_party/brotli`)** — *DONE 2026-06-09.*
  brotli v1.2.1 minus `http.go`; `tools/verify_brotli_provenance.go` proves 92 files byte-identical vs sum.golang.org. Survives re-vendor.
- **T-004 — Harden untrusted-SVG parser** — *DONE 2026-06-09.*
  recover + 10 MiB cap + 30s timeout + `FuzzRenderSVGBuiltinOKSVG` (~11M execs/30s, 0 panics). USER DECISION: 10 MiB, all four pieces.
- **T-005 — Release gate** — *DONE 2026-06-09.*
  `tools/releasegate.go`, 7 checks: reproducible build, nm invariants (non-stripped twin), brotli provenance, govulncheck, vet, `go test ./...`. 7/7.
  Links: blocked-by=T-002,T-003,T-004,T-006,T-008,T-009; supersedes=T-001
- **T-006 — `fmt.Fprintln` vet nits** — *DONE 2026-06-09.* Dropped redundant `\n` (6 sites). vet clean.
  Links: spawned-by=T-002
- **T-007 — Vestigial renderer flags** — *DONE 2026-06-09 — keep as compat-only.*
  `--renderer`/`--visual-renderer` + `renderSVG`'s `renderer` param are inert (oksvg hardwired); kept as compat-only. Reopen if removal wanted.
  Links: spawned-by=T-002
- **T-010 — Encode round-trip self-verification** — *DONE 2026-06-09.*
  `verifyEncodeRoundtrip` in `cmdEncode`: in-memory decode with selected policy, error + non-zero exit before writing on mismatch. `--no-verify-roundtrip` opt-out.
  Links: related=T-008,T-011
- **T-011 — Encoder/decoder eligibility-agreement bug** — *DONE 2026-06-09 (found by T-008).*
  Carrier eligible-before / integer-like-after → silent loss. Fix: `encodeStreamIntoSVG` consumes a carrier only if it round-trips. Regression `TestEncodeNearIntegerCoords`.
  Links: spawned-by=T-008

## Phase 1 — testing (in progress)

- **T-008 — Core correctness / heuristic tests** — *STARTED 2026-06-09.*
  Landed: round-trip (`TestEncodeRoundtripExactRecovery`), eligibility (`TestCarrierEligibility`), packing (`TestEncodeDecodeNumberRoundtrip`). Carrier is string/decimal-based. Remaining: full magnitude/large-coordinate matrix.
  Priority: P2
  Links: related=T-009
- **T-009 — Stealth / fidelity tests** — *STARTED 2026-06-09.*
  Visual fidelity via `auditDistortion` (rasterized diff); structural invariants via `TestCarrierEligibility`. Remaining: fuller fidelity matrix. Out of scope: statistical-steganalysis resistance.
  Priority: P3
  Links: related=T-019

## Phase 2 — DETECT layer / source-plausible carriers

DETECT → CONSTRAIN → STRATEGIZE; the DETECT layer is the objective function, built first.

- **T-012 — Research: perceptual-substitutive ("lossyWAV-style") carrier** — *DONE 2026-06-09.*
  Additive carriers are SVGO-fragile; substitutive (quantize-to-floor) is optimizer-stable; free-bit budget = `floor(log10(scale/τ))`. Limit: high-entropy LSBs detectable by chi-square/RS/SPA, unproven for SVG coords.
- **T-013 — Numeric-style DETECT layer + precision floor** — *DONE 2026-06-09.*
  `svgsteg_plausibility.go`: `numericSuspicionScore` (natural=0 vs encoded=10) + `analyzeCanvasPrecision` / `meaningfulDecimals = floor(log10((renderPx/vbExtent)/subPixelPx))`. XML-shape/fingerprint groups → T-015.
  Links: informed-by=T-012; related=T-015
- **T-014 — Capacity-vs-stealth ladder sweep** — *DONE 2026-06-09.*
  `TestCapacityStealthSweep` + `TestLadderSweep` (powers-of-two payloads × config ladder; capacity/bloat/overhead/susp). High-precision docs carry ~free; INFEASIBLE boundary quantifies headroom.
  Links: blocked-by=T-013,T-015
- **T-015 — XML-syntax + tool detector + line-length/blob (axis 2)** — *DONE 2026-06-09.*
  `analyzeXMLStyle` + `detectSVGTool` (explicit + style-inferred; pegs svgo-stripped) + `analyzeLineLengths` (blob-line guard). Real-export archetypes drove the detector + `genStyledSVG`.
- **T-016 — Perceptual axis-1 upgrade** — *FUTURE.* SSIM/CIEDE2000 vs naive pixel-count.
  Links: related=T-009,T-019; child-of=T-032
- **T-017 — Tool-consistency validation + per-tool corpus** — *DEFERRED.*
  Strip fingerprint or match detected tool's output capability; mode (b) needs a multi-sample-per-tool corpus.
  Links: blocked-by=T-015
- **T-018 — Layered stealth instrumentation** — *post-check DONE 2026-06-09; live-tracking DEFERRED.*
  `analyzeSourcePlausibility` composite (stealth analog of T-010). Live per-carrier tracking is invasive → deferred.
  Links: composes=T-013,T-015; related=T-010
- **T-019 — Production `analyzeEncode` + ladder consumer + `auditDistortion`** — *DONE 2026-06-09.*
  Production `analyzeEncode` (capacity/bloat/overhead/compR + raw `StreamBytes`/`carrierExp`) + `auditDistortion` = full capacity/distortion/suspicion audit. Copyright-safe `genStyledSVG` fixtures. Follow-up: wire into `encode --source-check` / `inspect`.
  Links: composes=T-018; supersedes=T-014
- **T-027 — Wire `analyzeEncode` into `encode --source-check` / `inspect`** — *OPEN.*
  `--source-check` flag on `encode` runs `analyzeEncode` + `auditDistortion` (rejects on fail); read-only `inspect` subcommand. The follow-up named in T-018/T-019.
  Priority: P2
  Links: blocked-by=T-019; related=T-018
- **T-028 — Encode-side source-plausibility constraints** — *DEFERRED.*
  Remaining CONSTRAIN/STRATEGIZE: no generated `id`/fingerprint on carrier paths; carrier-style modes (`--invisible-carrier-style auto|sibling|defs|opacity`); line-length budget (`--max-generated-line-len`, `--max-line-length-growth`; default `max(p90·2, 240)`); smart mode rejects profiles failing source budgets.
  Links: related=T-013,T-015,T-018,T-027
- **T-029 — Compact bootstrap header** — *DEFERRED.*
  Conservative fixed-reservation bootstrap carriers (version/length/mode), no magic string, legacy fallback. Also the compact-framing overhead lever for small payloads.
- **T-030 — Encrypted/auth control frame + carrier schema** — *DEFERRED.*
  AEAD control frame: logical fields, carrier schema, tamper-evident decode; builds on the bootstrap.
  Links: blocked-by=T-029
- **T-031 — Compact carrier maps + source-aware masking** — *DEFERRED.*
  Carrier-map encodings, automatic map selection, source-aware masking.
  Links: blocked-by=T-030
- **T-032 — Promoted perturbation, variable depth, substitutive carrier** — *DEFERRED.*
  Capacity-escalation ladder, climbing only as far as the payload needs: T0 substitutive (fill dead LSBs at the precision floor) · T1 additive canvas-calibrated bump (precision distribution stays unimodal) · T2 subdivision, curve/De-Casteljau over collinear · T3 underlay clone (proven by rendered diff). Plus perturbation budgets, variable depth, TPDF-dither shaping, SSIM/CIEDE2000 (child T-016). Every aggressive mode gated on the axis-1 rendered-diff regression. Home of the substitutive/Tier-0 carrier; separable from T-029–T-031, can be pulled forward.
  Links: informed-by=T-012

## Phase 3 — web / WASM (exploratory)

- **T-020 — Web/WASM feasibility** — *EXPLORATORY, confirmed 2026-06-09.*
  `GOOS=js GOARCH=wasm` builds (8.49 MB, `net.*`=0 — network-incapable carries into the browser). Same Go runs client-side, no JS rewrite.
- **T-021 — Minimal-WASM web build** — *STARTED — WASM encoder + generate UI built & browser-verified 2026-06-10.*
  - Codec registry + build tags: `GOOS=js` auto-drops all Go codecs incl. brotli (`!js`), uses browser `CompressionStream`; native `-tags nobrotli` drops brotli (~0.6 MB).
  - Size levers (8.49 MB): drop renderer+charset (~0.96 MB), drop codecs (~0.6 MB), TinyGo audit (<1 MB, T-035), HTTP gzip (~3× transfer).
  - WASM bridge (BUILT): `main_cli.go` (`!js`) / `main_wasm.go` (`js`, `svgstegEncode` via `js.FuncOf`) + `wasm_exec.js`. Wasm 4.93 MB. In-wasm encode == native (LinkedIn URL → 97 B stream, +291 B, comp none).
  - `index.html` (BUILT): swipe/diff/side-by-side comparator + generate flow (carrier A + URL + tunables → `svgstegEncode` → B → diff + download). LinkedIn-only gate in the wasm (`isLinkedInURL`, hardened 2026-06-10: host allow-list {linkedin.com, www.linkedin.com} + `/in/<username>[/]` structure + Unicode-inclusive username allow-list rejecting delimiter/control/bidi/zero-width; regex-free). PENDING: adversarial payload slider; Pages deploy workflow.
  - Acceptance (responsive): pointer/touch swipe, ≥44px tap targets, narrow-screen controls. Comparator landed 2026-06-09; generate UI must match.
  - Carrier: user uploads their own SVG (LinkedIn logo is copyrighted, not baked into the page); `inline_svg.go` could bake a CC0 default later. Renderer-drop + TinyGo = T-035.
  Priority: P1
  Links: blocked-by=T-020,T-026; related=T-019
- **T-035 — TinyGo adoption** — *EPIC — STARTED; verify-first (user decision 2026-06-10). Children gate adoption.*
  Replace the Go runtime in the `GOOS=js` wasm with TinyGo to cut size. Baseline (stdlib-Go) 4.88 MB raw / 1.35 MB gzip-9 (`-s -w` → 4.78 / 1.32); renderer already DCE'd, so the bulk is the Go runtime (target <1 MB). `-s -w` is a free ~99% win — ship it on the Pages build regardless. TinyGo (v0.41.1, Apr 2026, LLVM) is a compiler in the build TCB (Trusting-Trust), so staged: MVP verified adoption (T-036, gating) → ongoing output-parity (T-037). Adopt only if the size win justifies the TCB cost.
  Priority: P3
- **T-036 — TinyGo MVP (verified adoption)** — *OPEN — actionable now; gating; first child of the epic.*
  Verify the compiler → compile → verify the output:
  1. Verify the compiler (identity/integrity). TinyGo ships no checksums/signatures/SLSA for raw binaries (2026-06-10) → prefer the official `tinygo/tinygo` Docker image pinned by digest (the digest is the content hash; the container sandboxes). Verify image provenance (SLSA/cosign/SBOM), scan `trivy`/`grype`, cross-check the digest. Fallbacks: scoop/Homebrew pinned-hash, or build-from-source (verified tag). Observed (Docker Hub, 2026-06-10): 71 tags, ~2-mo cadence to 0.31.x; `0.41.1` = `latest` = one digest `sha256:2b41…58ba` (no tag drift, single-source — cross-verify before pinning).
  2. Prove the compiler isn't malware. Compile in a locked-down container (`--network none`, read-only source, non-root) + behavioral watch (DNS/egress) on first run.
  3. Make it compile. Renderer source-split behind `//go:build !js`; compat fixes (`js.ValueOf(map)` → hand-built JS object; crypto/rand; regexp). Build, `-s -w`, measure vs baseline.
  4. Check the binary. VERIFIED 2026-06-10: `go tool nm` can't read any wasm ("unrecognized object file", even Go 1.26's own); `go version -m` likewise empty. So the net=0 / capability gate MUST use wasm-native introspection (import-section analysis), for both Go and TinyGo output. Scan for unexpected host imports.
  Adopt only after 1–2 pass. WAIT for approval before any install.
  Priority: P2
  Links: child-of=T-035
- **T-037 — TinyGo↔stdlib output-parity checks** — *OPEN — non-gating; ongoing once the MVP build exists.*
  Deep compensating control for the compiler-in-TCB risk. Compare TinyGo- vs stdlib-Go-built wasm: (a) crypto/rand randomness stays CSPRNG-grade; (b) encode parity (same carrier+URL → same 97 B stream + identical decode); (c) determinism/byte-identical where expected; (d) capability diff via the wasm import-section. Gates nothing; any divergence is a stop signal. Re-run on each TinyGo bump.
  Priority: P3
  Links: child-of=T-035; blocked-by=T-036
- **T-047 — wasm-opt / binaryen size-optimization exploration** — *EPIC — OPEN; wasm-slimming lever independent of TinyGo (composes with it). Children gate the tool adoption.*
  Post-process the wasm with binaryen `wasm-opt` (`-Oz`). Unlike TinyGo (swaps the runtime), this optimizes the emitted wasm → applies to the current standard-Go build now, and composes with TinyGo later. Measure standalone, then multiply with TinyGo. External fetch-and-run → gated adoption.
  Priority: P3
  Links: related=T-021,T-035,T-040
- **T-048 — wasm-opt SCA / supply-chain verification** — *OPEN — GATING; verify-first before any install; first child.*
  binaryen/`wasm-opt` is a fetch-and-run → full protocol first. Pick + justify one channel (npm `binaryen`, GitHub releases, Homebrew/apt, or build-from-source). Verify identity, version (not "latest"), maintainers, CVEs, signatures/attestation; hash-pin the artifact. Present findings + WAIT for approval. (Mirrors T-036.)
  Priority: P3
  Links: child-of=T-047
- **T-049 — wasm-opt integration + results** — *OPEN — non-gating once T-048 clears; the measurement.*
  Apply `wasm-opt` (`-O2`, `-Oz`) to the current 3993 KB raw / 1108 KB gz wasm; record raw + gzip-9 savings and functional parity (`svgstegEncode`, `svgstegDiffPixels` still callable; parity harness byte-identical). Compose with TinyGo (T-036), record stacked result. Decide whether to bake a verified-pinned step into the build. Report chained to the input wasm hash.
  Priority: P3
  Links: child-of=T-047; blocked-by=T-048; related=T-036
- **T-050 — Optimized SVG/path state-machine scanner (partial regexp sweep)** — *OPEN — wasm-size + steg-correctness lever; a partial de-regex.*
  Replace regex on the ENCODE/hot path with a hand-written state machine: (1) wasm size — drop `regexp` from the wasm (169 refs); (2) steg correctness — surgical byte-preserving coordinate edits that do NOT normalize/reformat, preserving carrier + source fingerprint (T-013/T-015).
  - Two state machines: (a) XML-level scanner locating path/numeric attribute values without a full `encoding/xml` round-trip; (b) tokenizer for the path `d` mini-language for in-place number edits.
  - Tokenizer must handle: implicit repeated commands, delimiter-less numbers (`1.5.5` → `1.5`, `.5`), leading `+`/`-`, scientific notation, arc-flag digits.
  - PARTIAL sweep — target only the hot/wasm-critical regex; LEAVE DETECT-layer heuristics (T-013/T-015) on regex (analysis path, not hot path). Document swept vs kept.
  - Acceptance: `regexp` refs in the wasm drop (measured) + size delta; encode round-trip + eligibility tests green; fuzz the tokenizer (no panic, byte-preserving).
  Priority: P3
  Links: related=T-047,T-040,T-008,T-013,T-015
- **T-051 — Golden carrier fixtures + SVGOMG adversarial-input corpus** — *OPEN — test infrastructure; shared inputs for the carrier-boosting tickets.*
  Two golden carriers anchor the quality spectrum; SVGOMG generates an expanding adversarial corpus:
  - `linkedin.svg` (~1.2 KB) — NATURAL carrier: precision intact → eligible carriers; embeds at 0% distortion + clean plausibility pass.
  - `linkedin.mini.svg` (~0.84 KB) — ADVERSARIAL carrier: SVGOMG rounds precision to integer-only coords → zero natural carriers; embedding falls back to invisible carrier (+278% bloat) and DETECT correctly returns pass=false (styleDrift). Inlined losslessly + sha256-pinned (`linkedinMiniCarrierB64`).
  - SVGOMG as adversarial-input source (future): plugin toggles (round precision, `removeViewBox`, `convertPathData`, …) each emit a carrier-hostile variant; same toggles double as detector coverage for T-013/T-015.
  - Corpus tests the boosting levers: (a) path splitting/subdivision (`--subdivide`); (b) LSB stealth ↔ capacity (T-012); (c) invented/invisible paths (`--allow-invisible-carrier`, T-028).
  Priority: P3
  Links: related=T-012,T-014,T-028,T-046,T-015
- **T-052 — EPIC: Vertex inspector (Both mode)** — *OPEN — epic; children T-054 (MVP), T-055 (matching).*
  Make "a coordinate changed" tangible: draw path vertices on the Both-mode render, hover/tap shows the coordinate, reveal Bézier control handles, ultimately draw each stego move from → to.
  - Architecture (safe + cheap): leave the untrusted SVG as `<img>` (no script → no XSS) and overlay a separate `<svg>` with the same `viewBox`/`preserveAspectRatio` holding only `<circle>` markers in user-space (free user-space→pixel map, zero XSS surface). Native `<title>` = free tooltips.
  - Shared dependency: the path-`d` parser, built in the MVP child = T-050.
  Priority: P3
  Links: related=T-050,T-021,T-038
- **T-054 — Vertex inspector MVP: dots, hover coords, altered-coloring** — *OPEN — first child of T-052.*
  Parse `d` → vertices; overlay a matching-viewBox `<svg>` of `<circle>` dots over each Both-mode image; hover/tap → coordinate via `<title>`. Bézier control handles if cheap. Color by altered vs unaltered: walk A and B in lockstep (1:1 index, exact without `--subdivide`) and compare each vertex (changed → amber, unchanged → muted). No proximity, no map.
  Priority: P3
  Links: child-of=T-052; related=T-050,T-021
- **T-055 — Vertex inspector: subdivide 1↔N matching + move arrows** — *OPEN — second child of T-052.*
  Without `--subdivide` structure is identical → 1:1 by index (T-054 rides on this). Hard remainder: under `--subdivide`, B gains inserted vertices with no A counterpart (1↔N) — associate them to their parent A segment and draw each move as a from → to arrow. 1↔N lineage is blocked-by T-056 (proximity breaks where subdivide adds points).
  Priority: P3
  Links: child-of=T-052; blocked-by=T-056; related=T-050
- **T-056 — Encoder debug mutations-map (out-of-band)** — *OPEN — ground-truth side-channel for matching.*
  Opt-in `EncodeSVG` side-channel emitting exact per-coordinate changes: `[{pathIdx, cmd, vtxIdx, axis, from, to, byteOffset, subdividedFrom?}, …]` (`--debug-mutations` / wasm flag). Records subdivision lineage → the 1↔N mapping T-055 needs.
  - SECURITY — debug-only, NEVER shipped. The map pinpoints every carrier location (a self-fingerprint, cf. T-013/T-028). Default off, never in production output. Not the bootstrap header (T-029).
  Priority: P3
  Links: related=T-019,T-027,T-028
- **T-053 — Self-bootstrapping decode: carrier-policy sweep (stopgap) → canvas-derived (clean)** — *OPEN — USER DECISION 2026-06-11: brute-sweep stopgap, fingerprint-free.*
  Decode needs the carrier-policy out-of-band today (a bootstrap problem). The carrier-policy is FORMAT, not a secret (only the passphrase is secret), so self-bootstrap it without a fingerprint.
  - STOPGAP (chosen) — brute-force sweep + SHA-256 oracle. Sweep the bounded grid (visible-precision 0-8 × min-existing-decimals 0-8 × {decimalize-integers, skip-integer-like, skip-simple-fractions}) ≈ 648 combos, sub-second, early-exit; ACCEPT only the policy whose recovered stream passes SHA-256 framing (FP ≈ 2⁻²⁵⁶). PIN the continuous knobs. Sweeps FORMAT only; reads, doesn't write → no fingerprint.
  - LONG-TERM (cleanest) — canvas-derived policy. Encoder + decoder derive the same policy from the SVG (T-013 floor): zero sweep, zero header, fingerprint-free.
  - REJECTED — bootstrap header (T-029): adds a fixed-format region = a fingerprint. Avoid, per USER.
  Priority: P2
  Links: related=T-013,T-029,T-046,T-027
- **T-038 — Web app CSP + XSS hardening** — *OPEN — P0 (USER 2026-06-11); gates public launch.*
  The page renders user-supplied SVG (carrier A, generated B) and ships inline scripts — both lock down before public.
  - XSS: SVG can carry `<script>`/event handlers; current mitigation renders via `<img>`/`<canvas>` (`toImage`) where browsers don't execute SVG script — preserve that (never inject untrusted SVG as inline `<svg>`); URL is LinkedIn-gated; steg output is coordinate-only.
  - CSP: GitHub Pages can't set headers → `<meta http-equiv>` CSP: `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self' data: blob:; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'`. Prereq: move inline JS → external `app.js` (so `'self'` covers it, no `'unsafe-inline'`). Primary control = HTTP CSP header; static-host compensating control = meta-CSP + external/hashed scripts + preview noindex.
  - SRI (static vs dynamic, USER 2026-06-11): static includes (footer.js, wasm_exec.js, future app.js) carry `integrity=` in committed HTML, enforced by the T-063 gate. The build-generated wasm can't (hash changes per build); its integrity is injected/verified at publish by a GHA step, as are inline-script CSP hashes.
  - Integrity-Policy (verified 2026-06-11, MDN): would make the browser refuse un-hashed script/style but is response-header-only (no `<meta>` fallback), so GitHub Pages can't deliver it. The T-063 gate is the build-time compensating control; revisit only on a header-capable host.
  Priority: P0
  Links: related=T-021,T-025,T-057,T-063
- **T-057 — SHA-pin every GitHub Actions reference (verified)** — *DONE 2026-06-11 — 19/19 `uses:` pinned + enforced.*
  Every `uses:` across all four workflows (`ci`, `pages`, `release-provenance`, `renovate-pr-audit`) pinned to a verified commit SHA. Each tag→SHA resolved two independent ways (`gh api commits/{tag}` + `git ls-remote ^{}`, required to agree), signature checked, age ≥48h. The 9 actions: harden-runner@9af89fc v2.19.4, checkout@df4cb1c v6.0.3, setup-go@4a360112 v6.4.0, upload-artifact@043fb46d v7.0.1, download-artifact@3e5f45b2 v8.0.1, cosign-installer@6f9f1778 v4.1.2, attest-build-provenance@a2bbfa25 v4.1.0, attest-sbom@c604332 v4.1.0, slsa-github-generator@f7dd8c54 v2.1.0.
  - Compensating-control acceptance: the slsa-github-generator commit is `unsigned` upstream (intrinsic — SLSA's trusted-reusable-workflow verifies its own ref at runtime via OIDC, not commit GPG); pinned by two-protocol SHA + official non-prerelease release tag. Documented in the YAML + SUPPLY_CHAIN.md §11.
  - Enforcement: `tools/pingate.go` (fail-closed; every `uses:` must be 40-hex SHA) wired into `ci.yml` + `releasegate.go` (check 10); proven both sides (clean pass + catches `@v4`).
  - The drafts' `@PIN_VERSION` tool installs + comparator stubs are out of scope (not `uses:`); they keep both workflows non-deployable, see T-033. Spine go-live: push + Pages source = Actions + T-069 required-checks.
  Priority: P0
  Links: related=T-038,T-005,T-066,T-064,T-033
- **T-058 — Public-claims audit before launch** — *OPEN — P0; gates public release.*
  Check every visitor-facing claim (web/ copy, docs/, shipped comments) against the code; correct any that overstate it. Done: "no renderer in the wasm" (0 oksvg symbols in svgsteg.wasm), archetypeClasses synthetic-geometry wording. Remaining: rest of web/ + docs/ copy. Best run after T-059 (final web/ layout); soft ordering, not a blocker.
  Priority: P0
  Links: related=T-038,T-021,T-059
- **T-059 — web/ static-vs-dynamic split before launch** — *DONE 2026-06-11 12:17:39 PDT.*
  Static (index.html, parity.html, wasm_exec.js, .nojekyll) at web/ root; generated (svgsteg.wasm, parity renders) under web/out/ (gitignored). Fetch paths point at `out/`, verified by loading both pages. The GHA publish (gated on T-038/T-057) builds wasm + parity into web/out/.
  Priority: P1
  Links: related=T-021,T-038
- **T-060 — Parity: patched-vs-upstream oksvg toggle** — *DONE 2026-06-11 13:13:44 PDT.*
  parity.html footer toggle flips the oksvg (A) column between PATCHED (`img/`) and PRISTINE UPSTREAM (`img-upstream/`) and re-sweeps; default patched. Upstream shaded against the patched per-metric baseline (`baseMax`) so the regression reads red (stroke fixtures saturate; `fill` stays green). Footnote credits oksvg (BSD-3) + explains the stroke patch.
  - Build: `go run tools/renderparity.go --variant patched` → `img/`; `go run -mod=mod -modfile=go.upstream.mod tools/renderparity.go --variant upstream` → `img-upstream/` (against go.sum-verified fyne-io/oksvg@v0.2.0, no new vendored code). Shipped CLI/wasm always use the patched build.
  Priority: P3
  Links: related=T-044,T-045
- **T-061 — Trailing-zero cleanup pass + plausibility reporting** — *OPEN — USER-requested; plausibility/stealth.*
  Final text pass stripping machine-looking trailing zeros from coordinates (e.g. `2.500000`), a structural plausibility tell. Must be carrier-aware: stripping can change a fixed-width carrier value and break decode — strip only non-carrier zeros, or make decode tolerate variable width. Reporting (USER): zeros cleaned — count, % of all coords, and % of modified (carrier) coords (the last is a detectability metric).
  Priority: P3
  Links: related=T-012,T-028,T-032
- **T-062 — WASM visual-check via browser-provided renderer** — *OPEN — USER-requested; follow-on to T-040.*
  The wasm encode can't run the visual budget check (no in-wasm renderer; visual-check func var stubbed in js, per T-040). The browser already renders SVG to canvas and diffs via `svgstegDiffPixels` (parity.html, T-044). Extend the T-040 abstraction so the js build's visual-check calls a JS-provided renderer (browser canvas) instead of stubbing.
  Priority: P2
  Links: related=T-040,T-044
- **T-063 — Integrity-enforcement gate: SRI on every static include + hash-check outputs** — *DONE 2026-06-11 17:07:45 PDT.*
  `tools/integritygate.go` (stdlib, regex): walks `web/*.html`, stratifies includes STATIC (committed) vs DYNAMIC (`out/`), FAILS if a STATIC SRI-eligible include (`<script src>`, `<link rel=stylesheet>`) lacks/mismatches `integrity=`. Modes: verify (CI-fail), fix (repair static hashes), inject (`{{integrity}}` for dynamic includes at publish). SRI-unsupported includes (`<img>`, `<link rel=icon>`) reported as info. Second layer hashes build outputs into `web/out/integrity-manifest.sha384`. releasegate check 8. Verified: verify passes, negative round-trip catches corruption (exit 1), `fix` repairs byte-exact.
  Priority: P1
  Links: related=T-038,T-057
- **T-064 — Publish orchestrator (build SSOT) + wasm runtime integrity** — *DONE 2026-06-11 19:28:26 PDT.*
  `tools/publish.go` is the single source of truth for build/publish, run identically locally and by CI (thin wrapper: checkout → setup-go → `go run tools/publish.go`). Steps: integritygate verify → build wasm (`-trimpath`, deterministic) → renderparity (patched + upstream) → assemble `dist/` → compute `sha384(wasm)`, inject into dist HTML (`{{wasm-integrity}}`) → optional `--serve`. Output integrity: tag `integrity=` can't cover `WebAssembly.instantiateStreaming`, so the loader fetches the bytes, `crypto.subtle.digest('SHA-384', …)`, compares to the injected hash, refuses to instantiate on mismatch (HTTPS + localhost; raw `web/` dev keeps the placeholder + warns). Reproducible build makes local hash == CI hash. Remaining: the thin GHA workflow with SHA-pinned actions (T-057). Loaders tested positive + tamper-rejection.
  Priority: P1
  Links: related=T-038,T-057,T-063,T-059
- **T-065 — Capability-regression gate (capgate)** — *DONE 2026-06-11 22:13:58 PDT — releasegate check 9.*
  `tools/capgate.go` snapshots the transitive package surface of each shipped artifact and FAILS if a build adds any package vs `tools/capability.baseline`. Two levels: source (`go list -deps` for the native CLI + GOOS=js wasm) and binary (`go tool nm` on the non-stripped CLI, no excess-cap package LINKED post-DCE). `hasExcessCaps` flags net/http/rpc/smtp/crypto-tls/os-exec/plugin/runtime-cgo additions (parse-only net/url, net/netip excluded). Fails closed (go-list error, missing baseline, empty package list, build/nm failure all exit non-zero). Verified at the package level. capslock + cap-diffs are the future upgrade (T-033); the wasm binary-level host-import check stays T-039.
  Priority: P2
  Links: child-of=T-066; related=T-039,T-033,T-001
- **T-066 — EPIC: SCA / CI-CD / GHA hardening** — *EPIC — STARTED (USER 2026-06-11); cross-cutting accounting for the secure build/publish chain.*
  Umbrella for every "pin it, scan it, attest it, capability-bound it, deploy it" workstream; tools integrated as deliberate children (verify-first per adoption).
  - DONE children: integritygate/SRI (T-063) · publish SSOT + runtime wasm integrity (T-064) · capgate (T-065) · verified action-SHA pinning + pingate (T-057). All wired into releasegate.
  - OPEN children: the SHA-pinned spine `pages.yml` (T-057) · CSP + inline-JS→`app.js` (T-038) · wasm host-import capability check (T-039) · SLSA L3 provenance + Renovate choreography (T-033).
  - FUTURE tool children (propose → verify-first → integrate, each its own ticket): cosign · osv-scanner · zizmor · capslock + cap-diffs · slsa-github-generator / attest-build-provenance · Chainguard/Wolfi base via GHCR mirror.
  - Target shape: the gate-DAG — CI gates fed by a Renovate loop; publish = build → SBOM → scan → sign → attest → deploy. Base choice (golang:1.26-bookworm pinned vs Chainguard-mirror vs ubuntu) tracked here.
  Priority: P1
  Links: related=T-063,T-064,T-057,T-038,T-039,T-033
- **T-067 — CodeQL default-setup code scanning (Go + JS)** — *OPEN — XSS/injection taint layer (1 of 3); serves T-038.*
  Enable CodeQL default setup (Settings → Code security) — one toggle, no workflow file: free on public repos, GitHub-managed suite, auto-detects Go + JS, taint-tracks XSS/injection on push/PR/schedule. Default setup → no `codeql-action` to SHA-pin (adds a taint layer while reducing action surface). Generic flows; project-specific sink rule is T-068, wasm binary stays T-039/capgate. Verify on first run: Go autobuild with `-mod=vendor` (fall back to advanced + explicit build if it chokes).
  Priority: P2
  Links: child-of=T-066; related=T-038
- **T-068 — Stdlib DOM-XSS sink gate (sink ratchet)** — *OPEN — XSS/injection custom layer (2 of 3); serves T-038.*
  capgate-shaped stdlib tool: grep `web/*.{html,js}` for dangerous DOM sinks (`innerHTML=`, `insertAdjacentHTML(`, `outerHTML`, `document.write`, `.srcdoc`, `eval(`, `new Function`, inline `on*=`), baseline + diff, fail on new usage so each earns a trusted/escaped review. No npm/Python/network. Pins what CodeQL's default suite won't phrase as project rules: index source-diff renders user-SVG coordinate text (must be `textContent`); footer.js `insertAdjacentHTML` (static = safe) + parity `table()` `innerHTML` (generated) baselined as known-safe. Fail-closed; wire into releasegate.
  Priority: P2
  Links: child-of=T-066; related=T-038,T-063
- **T-069 — Repo-hardening strike list (give the gates teeth)** — *OPEN — enforcement + free native layers; child of T-066.*
  One pass of repo settings/toggles turning detection gates into enforced ones + adding free GitHub-native layers. Detection without this is advisory.
  - [ ] Branch protection on `main` — block force-push, require PR, linear history.
  - [ ] Required status checks — the `ci.yml` gates (vet / test / capgate / integritygate / pingate). PRE-REQ CLEARED: `ci.yml` exists + runs green (T-057); unblocked once the spine is pushed and the checks report once on a PR.
  - [ ] Pages source = GitHub Actions — so `pages.yml` is the deploy path.
  - [ ] Secret scanning + push protection (free on public repos).
  - [ ] Dependabot security alerts (free).
  - [ ] OSSF Scorecard action (surfaces missing branch protection / signed releases) — tiny SHA-pinned workflow, verify-first.
  - [ ] Deploy-environment protection — the `github-pages` environment limits who/what can deploy.
  Priority: P1
  Links: child-of=T-066; related=T-057,T-038
- **T-070 — Input resource bounds for untrusted SVG (anti-DoS)** — *OPEN — app robustness; separate axis from the SCA epic.*
  We parse untrusted SVG; a malformed/huge input must not hang or OOM the CLI/wasm. The render path has a timeout, but the encode/parse path's bounds are unverified. Audit + enforce: max input bytes, max path coordinate count/length, max recursion/iteration depth, parse time budget — reject past the bound. Covers CLI + wasm encode entrypoints; add fuzz cases at each limit.
  Priority: P2
  Links: related=T-046,T-008,T-009
- **T-039 — wasm capability introspection + signed attestation** — *OPEN — design; serves the gate, T-036/037, T-038.*
  A toolchain-agnostic, independently-verifiable capability attestation for the wasm artifact(s).
  - Keep `go tool nm` — it reads Go-toolchain wasm symbols (the symbol layer: is net linked?). Limits: strippable (run on unstripped) and a soft proxy (linked ≠ reached). Likely can't read TinyGo's LLVM wasm — confirm empirically once T-036 exists.
  - Add an import-section reader (the capability layer). A wasm module can only call host functions in its import section → a runtime-enforced hard bound, strip-resistant. Thin stdlib reader cross-validated against `wasm-objdump -j import -x` (WABT) by differential test (no WABT runtime/CI dependency).
  - net=0 is layered: (1) nm → net not linked; (2) import section → host-capability bound, but Go-wasm imports the generic `gojs`/`syscall.js` bridge so net is reachable through it (not decisive alone); (3) CSP `connect-src 'self'` + `app.js` provably never calling fetch/XHR/WS (T-038). Compose all three; document coverage gaps.
  - Attestation chains to the collateral. in-toto Statement: subject = manifest of every output `{name, digest.sha256}`; predicate = toolchain (compiler + version + image digest + flags) · import set · nm-net summary · cross-check tool+version+agreement. Sign via the Sigstore/cosign/Rekor chain (T-033). Independently verifiable; the compiler image digest closes the Trusting-Trust loop.
  Priority: P2
  Links: related=T-033,T-037,T-038
- **T-040 — Optional renderer (build-tagged) — drop oksvg/image when unused** — *DONE 2026-06-10 11:45:40 PDT.*
  oksvg/image/rasterx/png renderer is an optional subsystem behind build tags → builds that don't need the visual-fidelity check link none of it (smaller binary + supply-chain surface). Independent of TinyGo, also its compile prereq (T-036).
  - Scheme (tag `norender`): `render_native.go` (`!js && !norender`) holds renderer + image imports; `render_stub.go` (`js || norender`) holds stubs. Core keeps image-free code (`DiffStats`, `renderDims`, `checkVisualBudget`, `copyFile`, `parseViewBox`).
  - Capability constant `rendererBuiltIn` bridges compile-time tag → runtime feature-gating. `validateOpt` refuses renderer-dependent features up front (`--visual-check`, `--emit-sidecars`, `diff`) with a clear message.
  - Fail-closed conveyance — absence-of-check ≠ pass: cmdDiff → error; diffSVGBytes → error so smart mode rejects with reason; auditDistortion → `ok=false` ("audit: UNAVAILABLE", never `0%`); emitEncodeSidecars → skip + logged note.
  - Browser fills the wasm's rendering gap: the wasm ships no Go rasterizer, but the browser's native rasterization does the pixel analysis (`<img>`→`<canvas>`→`getImageData()`). The audit relocates to JS/canvas, isn't lost.
  - Built 2026-06-10: `render_native.go` + `render_stub.go`; `rendererBuiltIn`; smart visual gate build-conditional + conveyance note; diff/sidecar/audit stubs fail-closed. Verified: native gate 7/7; `-tags norender` builds+tests, oksvg 0 · image 0, binary 7.84→6.05 MB, `diff` refused cleanly; wasm 4.93→4.08 MB. `diffImages` moved wholesale (pure `diffPixels([]byte)` lands in T-041).
  Priority: P2
  Links: related=T-036
- **T-041 — Pluggable rasterizer + pure pixel-compute (browser feeds all bitmap checks)** — *DONE 2026-06-10 12:12:53 PDT.*
  Browser canvas rasterization drives every bitmap-dependent check via a rasterize / compute split:
  - Rasterize (svg → RGBA): pluggable, environment-specific — oksvg (native) / browser `<canvas>` (wasm) / none (`-tags norender`). Only renderer-dependent layer.
  - Compute (RGBA → stats): pure Go on `[]byte` (`diffPixels` + visual-budget), no `image` pkg → universal, links in every build incl. wasm.
  - The abstraction is the `[]byte` RGBA contract, not one Go interface spanning both: native uses a Go `Rasterizer` interface behind the tag; browser canvas (async, single-threaded) feeds the same `diffPixels` via the wasm export.
  - Built 2026-06-10: `pixeldiff.go` pure `diffPixels([]byte)`; `diffImages` delegates via an `imageToRGBA` adapter; wasm export `svgstegDiffPixels`; `index.html` diff routed through it. Browser-verified: wasm `diffPixels` == native byte-exact (changed 1 / maxΔ 30 / mean 7.5); round-trip = 0 diff; gate 7/7.
  Priority: P3
  Links: blocked-by=T-040; related=T-021,T-039
- **T-042 — Prove smart-feature equivalence across rasterizers (oksvg ↔ browser canvas)** — *OPEN — verification.*
  Prove visual-gated smart features (profile selection by visual budget) work when driven by the browser's rasterizer. Layered, not pixel-identity:
  - Compute equivalence (byte-exact): same RGBA → native `diffPixels` and the wasm export → byte-identical stats. Isolates divergence to the rasterizer.
  - Rasterizer characterization: consumes the T-044 parity baseline.
  - Decision equivalence (end-to-end): smart-mode selection oksvg- vs browser-driven over fixtures → same profile chosen; flag threshold-straddling cases, decide tolerance/rasterizer-aware thresholds.
  - Harness: native side in Go tests; browser side headless (Playwright) feeding canvas pixels to wasm `diffPixels`; shared fixtures + report chained to file hashes.
  Priority: P3
  Links: blocked-by=T-044; related=T-021,T-039
- **T-043 — Inter-renderer noise floor as a steg-invisibility tell (dual-renderer diagnostic)** — *OPEN — research.*
  Prove/falsify: the steg perturbation is smaller than the disagreement between SVG rendering pipelines → it sits below the renderer-noise floor (a stronger tell than "looks the same").
  - Built on the T-044 dual/multi-renderer baseline.
  - Four renders, two divergences: steg signal = diff(orig, stego) within one renderer; renderer noise = diff(oksvg, canvas) on the same SVG. Tell: steg signal ≪ renderer noise.
  - Output: per-fixture floor and where the steg sits relative to it. Caveat: visual-axis tell only (XML-syntax + precision axes separate).
  Priority: P3
  Links: blocked-by=T-044; related=T-021,T-032
- **T-044 — Renderer parity: multi-source rasterization divergence baseline** — *DONE 2026-06-10 20:18:53 PDT — oksvg↔browser baseline built, measured + patch-validated; TinyGo 3rd source DEFERRED to T-036/T-037.*
  Measure how much rasterization sources disagree on the same SVG (renderer parity, separate from compute T-039 and decision T-042). Up to three sources: Go-oksvg (native), TinyGo-oksvg (T-036/T-037), browser canvas. Pairwise diffs factor out compiler effect (Go vs TinyGo oksvg) and rendering-engine effect (oksvg vs browser).
  - Built 2026-06-10 (oksvg↔browser, install-free): `tools/renderparity.go` rasterizes fixtures (4 synthetic + one real-world brand logo, loaded at runtime from a local gitignored asset dir, not committed) with oksvg → white-bg PNGs at 7 resolutions + `fixtures.json`; `parity.html` canvas-rasterizes the same SVGs at the same R×R + diffs via wasm `diffPixels`, with a click-to-inspect viewer (A/B/diff, amplify slider).
  - oksvg stroke-width bug CONFIRMED (`tools/strokecheck.go`): oksvg renders `stroke-width` at constant device-pixel size regardless of `SetTarget` (scales geometry, not stroke width) — a spec-noncompliance (persists in fyne-io/oksvg v0.2.0; upstream PR via T-045). Our `stroke-width="2"` is correct (unitless = user units, which scale). Steg detection unaffected (bug cancels in the within-renderer diff); only confounds oksvg-vs-browser parity.
  - Sweep (corrected): NO irreducible floor — the earlier "plateau" WAS the stroke bug. Strokeless fixtures follow the clean `~1/R` law all the way down (`fill`→0.19%, `linkedin`→0.58% at 1024). Use strokeless fixtures for the steg-relevant floor.
  - LEARNINGS — post-patch floor (oksvg↔browser, % pixels differing): with the T-045 stroke patch, all fixtures follow `~1/R`, no plateau. Mean changed% by R: 16→24.1 · 32→12.3 · 64→6.3 · 128→3.4 · 256→1.9 · 512→0.97 · 1024→0.49 (meanΔ 1.47→0.031). At 1024px two known-good renderers agree on ~99.5% of pixels, maxΔ ≤ ~115/255; residual is anti-aliasing implementation, concentrated at edges (interiors byte-match). The floor is resolution-dependent (a curve, not a number). Necessary-not-sufficient: the visual-XML/source smell test (T-013/T-015) and statistical steganalysis (T-009, deferred to T-046) are independent axes.
  - TinyGo 3rd source DEFERRED to T-036/T-037.
  Priority: P3
  Links: blocked-by=T-041; related=T-036,T-039,T-046
- **T-045 — oksvg fork audit + dependency-freshness explore** — *DONE 2026-06-10 — adopted `fyne-io/oksvg v0.2.0` + vendored a provenance-checked stroke-width patch (`third_party/oksvg`); dogfooded vs browser; PR-ready upstream.*
  Decide whether to move off the unmaintained `srwiley/oksvg` pin (2022-10-11) that T-044's stroke bug exposed. Fork landscape audited read-only (GitHub API) 2026-06-10: `fyne-io/oksvg` leads — +26/−0 vs upstream (clean superset), Fyne-backed, release tags, BSD-3, lean; `walterschell` +3 solo; `qiniu` −19 stale. All BSD-3.
  - Dep-freshness case is MOOT: our module already resolves x/net v0.55.0 / x/image v0.41.0 / x/text v0.37.0 (MVS max), newer than any fork declares, so a swap freshens nothing transitive; buys only 26 oksvg-source commits. Bar to switch is high; default = stay on the integrity-locked pin.
  - DECISION 2026-06-10 19:13 PDT — ADOPTED `github.com/fyne-io/oksvg v0.2.0` (import-rewrite in 4 files, not a replace; `rasterx` stays `srwiley`). Verified pre-fetch (read-only): clean +26/−0 superset, no new capability (lone `os` flag was the `ioutil`→`io` modernization; nm confirms no net/exec/plugin), API-compatible. Post-adopt: hash-locked (`h1:mxcGU2dx6nwjJsSA9PCYZDuoAcsZ/OuJlvg/Q9Njfo8=`), native/wasm/norender build, x/* held at 0.55/0.41/0.37, gate 7/7. Rationale: a maintained fork that shipped relevant fixes (parser empty-string crash, Staticcheck, float-percentage spec compliance). Caveat: does NOT fix the stroke-width bug; adds a 2nd renderer trust root while `srwiley/rasterx` stays unmaintained.
  - PATCHED + DOGFOODED 2026-06-10 19:44:46 PDT — stroke-width fix vendored. `third_party/oksvg` = fyne-io/oksvg@v0.2.0 byte-for-byte (106 files) + a 1-file patch (`svg_path.go`: scale `LineWidth` by `√|det(M)|`), behind `replace … => ./third_party/oksvg`. Custody: `tools/verify_oksvg_provenance.go` chains to sum.golang.org (`934ec3…` → patched `08edb3…`), gate check #4b (8/8). Geometric mean exact for isotropic scale, bounded approximation under anisotropy; degenerate/no-viewBox clamps scale to 1; `tools/strokecheck.go` covers uniform+anisotropic+degenerate. Dogfood: diagonal@1024 changed 2.19→0.73%, meanΔ 1.75→0.034, maxΔ 245→36; plateau + high-res meanΔ-rise gone.
  - Follow-up: upstream the patch as a fyne-io/oksvg PR (PR body = `PATCH-NOTES.md` + the `tools/strokecheck.go` repro).
  Priority: P3
  Links: related=T-044,T-039,T-036
- **T-046 — Steganographer strictness suite + payload-entropy documentation** — *FUTURE — adversarial validation; spun out of T-043/T-044.*
  A stego output must pass both smell tests: visual-raster (rendered pixels below the renderer-noise floor, T-043/T-044) AND visual-XML/source (numbers/XML look authored or tool-emitted, T-013/T-015). Source plausibility + statistical flatness are the binding constraints, not visual invisibility.
  - Document payload entropy: embedded bits are high-entropy; high-entropy coordinate LSBs are detectable by chi-square/RS/SPA regardless of visual imperceptibility (T-012). Quantify the entropy and where it leaks.
  - Strictness tests (later): opt-in adversarial suite scoring an encode against the full attacker toolkit — source smell (T-013/T-015), the raster floor (T-043/T-044), and the statistical tests T-009 left out of scope (chi-square/RS/SPA on coordinate LSBs). Measure resistance instead of assuming it.
  Priority: P4
  Links: related=T-009,T-012,T-013,T-015,T-043,T-044
- **T-025 — Public-release prep** — *OPEN — pre-public hygiene.*
  Before the repo goes public: add `.gitignore` (exclude private/copyrighted assets, build artifacts (`*.exe`, `svgsteg.wasm`), local tool/temp dirs, `*.steg.svg`), write `README.md` (what it is, build, usage, offline/network-incapable posture), confirm `git ls-files` tracks nothing private. LICENSE already present.
  Priority: P0
  Links: related=T-020
- **T-026 — Codec registry + build tags** — *DONE 2026-06-10 00:22:09 PDT.*
  Compression is a self-registering codec registry (`compression.go`) + build-tagged codecs (`compression_stdlib.go` `!js`; `compression_brotli.go` `!nobrotli && !js`); `none` always present. Verified: native gate 7/7; `-tags nobrotli` brotli symbols 428→0; `GOOS=js` drops all Go codecs (wasm 8.49→6.38 MB). Browser `CompressionStream` bridge lands in T-021. Unblocks T-021.
  Priority: P1

## Tooling (meta)

- **T-022 — Backlog tooling (epic)** — *IN PROGRESS — 1 child done, 1 open.*
  The `tools/backlog_graph.go` system. Children: read-only tool (T-023, done) + in-place write (T-024, not started). ONE typed directed graph (per-ticket `Links:`); trees are projections of a single edge type (`path` = blocked-by tree; `child-of`/`parent-of` = epic hierarchy).

- **T-023 — Backlog tool: read-only MVP** — *DONE 2026-06-09.*
  `tools/backlog_graph.go` (stdlib, read-only — every mode → stdout). Consume-boundary guarantees: file integrity, schema integrity (every ticket `**T-NNN — Title** — *status*` with a recognized status), zero-tickets guard, edge integrity (`-check`: dangling refs, self-loops, unknown verbs, blocked-by cycles), staleness (`verify`). Default path `BACKLOG.md`, override via `-f`/`--file`/`$BACKLOG_FILE`. Views: `graph` · `board` · `prio` · `ready`/`blocked` · `path`/`show` · `legend` · `export` (gh issues) · `repl`.
  Links: child-of=T-022

- **T-024 — Backlog tool: in-place `--write`** — *OPEN — core write done; conservation guarantees pending.*
  Bounded mutation of ONLY the `<!-- BEGIN/END GENERATED -->` region; ticket prose + `Links:` never tool-written. Conservation guarantee (no entry ever dropped):
  1. Marker-bounded — refuse if either marker is missing or appears ≠1×.
  2. Conserve-and-prove — build the proposed file, re-parse it, assert the ticket+edge model is unchanged AND every byte outside the markers is byte-identical; abort on any diff.
  3. Atomic — temp + rename; optional `.bak`.
  4. Verify-after — re-run `-check` + `verify`.
  Status (2026-06-11): `regen`/`write` (`regenInPlace`) does the marker-bounded in-place rewrite (replaced the old Python splice), but is a direct `os.WriteFile` today — guarantees 1–4 still remain.
  Priority: P3
  Links: child-of=T-022; blocked-by=T-023
- **T-033 — Adopt supply-chain audit + SLSA L3 provenance** — *OPEN — action SHAs pinned (T-057); rest pending.*
  Wire the choreography: Renovate (`minimumReleaseAge`, vuln fast-track, no automerge) + `renovate-pr-audit.yml` (CVE-posture diff, capslock capability diff, SBOM-completeness gate, code+binary scan — all fail-closed) + `release-provenance.yml` (reproducible build → SBOM → SLSA Build L3 via isolated generator → keyless cosign + in-toto SBOM attestation → Rekor).
  - Done: all action SHAs pinned + verified + pingate-enforced (T-057).
  - Remaining before these go active (still non-deployable): (1) bootstrap the scanner installs — four `@PIN_VERSION` placeholders (cyclonedx-gomod, osv-scanner, capslock, govulncheck) need version-pin + checksum under the §11 protocol; (2) implement the CVE-diff + capability-diff comparators (currently STUBS that `exit 1`); (3) fold SBOM-completeness + brotli-upstream-OSV into `releasegate.go`; (4) branch/tag protection + signed commits (gitsign); when (1)+(2) land, restore the target triggers (commented in each `on:` block).
  - Hazard handled (2026-06-11): both were tracked with live triggers (`on: release` / `on: pull_request`) that would FAIL while stub/`@PIN_VERSION` — now neutralized to `workflow_dispatch` only.
  - Tooling done: `tools/verify_action_pin.go` — Renovate-PR drift guard: `resolve` (print a verified PIN LINE) + `check` (re-resolve every pinned `uses:` two ways, assert it still equals the pinned SHA; reports sig + age, memoized, confirm-on-disagree so a flake never reads as tamper). Enhancement candidate: replace per-call `gh` with native `net/http` (one reused HTTP/2 connection to `api.github.com` via `GITHUB_TOKEN`; `git ls-remote` kept as independent 2nd protocol) — drops the `gh` dependency + rate-limit pressure, stays zero-dep.
  Priority: P2
  Links: related=T-005,T-025
- **T-034 — Retire brotli fork if upstream drops the net linkage** — *DEFERRED (external trigger).*
  The fork exists only because upstream `andybalholm/brotli` ships `http.go` (links `net/http`). Trigger: upstream removes `http.go`, gates it behind a build tag, or splits it to a submodule. Then: drop the `replace`, delete `third_party/brotli/` + `tools/verify_brotli_provenance.go`, `go get` upstream wholesale (restores `sum.golang.org` coverage), confirm nm `net = 0` holds. See `third_party/brotli/PATCH-NOTES.md`.
  Links: related=T-003,T-033

---

<!-- BEGIN GENERATED: tools/backlog_graph.go (do not hand-edit; run `go run tools/backlog_graph.go`) -->
## Linkages — generated graph view

*Derived from the per-ticket `Links:` lines by `tools/backlog_graph.go`. Do not hand-edit:
edit the `Links:` line on the ticket and regenerate.*

- **T-001** — blocked-by T-002,T-003,T-004 · superseded-by T-005 · related T-065
- **T-002** — blocks T-001,T-005 · spawned T-006,T-007
- **T-003** — blocks T-001,T-005 · related T-034
- **T-004** — blocks T-001,T-005
- **T-005** — blocked-by T-002,T-003,T-004,T-006,T-008,T-009 · supersedes T-001 · related T-033,T-057
- **T-006** — blocks T-005 · spawned-by T-002
- **T-007** — spawned-by T-002
- **T-008** — blocks T-005 · spawned T-011 · related T-009,T-010,T-050,T-070
- **T-009** — blocks T-005 · related T-008,T-016,T-019,T-046,T-070
- **T-010** — related T-008,T-011,T-018
- **T-011** — spawned-by T-008 · related T-010
- **T-012** — informs T-013,T-032 · related T-046,T-051,T-061
- **T-013** — blocks T-014 · composed-by T-018 · informed-by T-012 · related T-015,T-028,T-046,T-050,T-053
- **T-014** — blocked-by T-013,T-015 · superseded-by T-019 · related T-051
- **T-015** — blocks T-014,T-017 · composed-by T-018 · related T-013,T-028,T-046,T-050,T-051
- **T-016** — child-of T-032 · related T-009,T-019
- **T-017** — blocked-by T-015
- **T-018** — composes T-013,T-015 · composed-by T-019 · related T-010,T-027,T-028
- **T-019** — blocks T-027 · composes T-018 · supersedes T-014 · related T-009,T-016,T-021,T-056
- **T-020** — blocks T-021 · related T-025
- **T-021** — blocked-by T-020,T-026 · related T-019,T-038,T-041,T-042,T-043,T-047,T-052,T-054,T-058,T-059
- **T-022** — parent-of T-023,T-024
- **T-023** — blocks T-024 · child-of T-022
- **T-024** — blocked-by T-023 · child-of T-022
- **T-025** — related T-020,T-033,T-038
- **T-026** — blocks T-021
- **T-027** — blocked-by T-019 · related T-018,T-028,T-053,T-056
- **T-028** — related T-013,T-015,T-018,T-027,T-051,T-056,T-061
- **T-029** — blocks T-030 · related T-053
- **T-030** — blocked-by T-029 · blocks T-031
- **T-031** — blocked-by T-030
- **T-032** — parent-of T-016 · informed-by T-012 · related T-043,T-061
- **T-033** — related T-005,T-025,T-034,T-039,T-057,T-065,T-066
- **T-034** — related T-003,T-033
- **T-035** — parent-of T-036,T-037 · related T-047
- **T-036** — blocks T-037 · child-of T-035 · related T-040,T-044,T-045,T-049
- **T-037** — blocked-by T-036 · child-of T-035 · related T-039
- **T-038** — related T-021,T-025,T-039,T-052,T-057,T-058,T-059,T-063,T-064,T-066,T-067,T-068,T-069
- **T-039** — related T-033,T-037,T-038,T-041,T-042,T-044,T-045,T-065,T-066
- **T-040** — blocks T-041 · related T-036,T-047,T-050,T-062
- **T-041** — blocked-by T-040 · blocks T-044 · related T-021,T-039
- **T-042** — blocked-by T-044 · related T-021,T-039
- **T-043** — blocked-by T-044 · related T-021,T-032,T-046
- **T-044** — blocked-by T-041 · blocks T-042,T-043 · related T-036,T-039,T-045,T-046,T-060,T-062
- **T-045** — related T-036,T-039,T-044,T-060
- **T-046** — related T-009,T-012,T-013,T-015,T-043,T-044,T-051,T-053,T-070
- **T-047** — parent-of T-048,T-049 · related T-021,T-035,T-040,T-050
- **T-048** — blocks T-049 · child-of T-047
- **T-049** — blocked-by T-048 · child-of T-047 · related T-036
- **T-050** — related T-008,T-013,T-015,T-040,T-047,T-052,T-054,T-055
- **T-051** — related T-012,T-014,T-015,T-028,T-046
- **T-052** — parent-of T-054,T-055 · related T-021,T-038,T-050
- **T-053** — related T-013,T-027,T-029,T-046
- **T-054** — child-of T-052 · related T-021,T-050
- **T-055** — blocked-by T-056 · child-of T-052 · related T-050
- **T-056** — blocks T-055 · related T-019,T-027,T-028
- **T-057** — related T-005,T-033,T-038,T-063,T-064,T-066,T-069
- **T-058** — related T-021,T-038,T-059
- **T-059** — related T-021,T-038,T-058,T-064
- **T-060** — related T-044,T-045
- **T-061** — related T-012,T-028,T-032
- **T-062** — related T-040,T-044
- **T-063** — related T-038,T-057,T-064,T-066,T-068
- **T-064** — related T-038,T-057,T-059,T-063,T-066
- **T-065** — child-of T-066 · related T-001,T-033,T-039
- **T-066** — parent-of T-065,T-067,T-068,T-069 · related T-033,T-038,T-039,T-057,T-063,T-064
- **T-067** — child-of T-066 · related T-038
- **T-068** — child-of T-066 · related T-038,T-063
- **T-069** — child-of T-066 · related T-038,T-057
- **T-070** — related T-008,T-009,T-046
<!-- END GENERATED -->

---

## Pre-Phase-1 (done, foundational)

- Removed duplicate `setOptionDefaults` (build blocker); pinned+bumped deps (x/net 0.55.0, x/image 0.41.0,
  x/text 0.37.0, brotli 1.2.1, klauspost 1.18.6, oksvg/rasterx pinned); removed network source (`brotli/http.go`)
  → 55→0 net symbols; Stage-1 strip (oksvg sole renderer, removed `os/exec` + shell-outs) → 53→0 exec symbols.
