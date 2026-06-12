# third_party/oksvg — local patch notes

This tree is `github.com/fyne-io/oksvg@v0.2.0`, byte-for-byte from the Go module proxy
(verified against `sum.golang.org`), with exactly **one source file modified**. Chain of custody
is enforced by `tools/verify_oksvg_provenance.go`: every file must be byte-identical to upstream
except those listed at the bottom.

## Why vendor + patch instead of importing directly

A filesystem `replace github.com/fyne-io/oksvg => ./third_party/oksvg` lets us carry a minimal
local fix while it goes upstream (fyne-io has issues disabled; the fix is destined for a PR). The
`replace` bypasses `go.sum` / `go mod verify`, so the provenance verifier is the **compensating
integrity control** (same pattern as `third_party/brotli`).

## The patch — `svg_path.go`: stroke-width now scales with the render transform

**Bug (present in fyne-io v0.2.0 *and* srwiley upstream):** `SvgIcon.SetTarget` scales path
*geometry* to the target size, but `DrawTransformed` hands `LineWidth` to rasterx's scalar-pen
stroker **raw** — so `stroke-width` renders in device pixels and does NOT scale with the
viewBox→viewport transform. Per SVG, `stroke-width` is in *user units* and must scale. Measured:
a `stroke-width=10` line in a 100-unit viewBox rendered **10px at 100/200/400/800px** targets,
where the spec/browser give **10/20/40/80**.

**Fix:** multiply `LineWidth` by `√|det(M)|`, the linear scale factor of the active transform
`M = mAdder.M`.

- `√|det|` is the **geometric mean** of the axis scale factors. For an **isotropic** (uniform)
  scale — `sx == sy` — it is **exact**.
- Under **anisotropy** (non-square viewBox→viewport, `sx ≠ sy`) the spec-correct stroke is an
  **elliptical pen** (width varies with path direction). rasterx's `SetStroke` takes a single
  scalar and cannot represent that, so `√|det|` is the **area-preserving single-scalar
  approximation** — always between `sx` and `sy`, error bounded by the scale anisotropy and
  vanishing as `sx → sy`. There is no universal "standard" scalar (After Effects uses the
  *arithmetic* mean; others a diagonal-pixel measure); we chose the geometric mean because it
  preserves the area-equivalent linear scale. A fully spec-correct fix would stroke in user space
  and transform the outline — a rasterx-pipeline change, out of scope for this minimal patch.
- **Defense:** a degenerate or missing-viewBox transform (e.g. `SetTarget` divides by
  `ViewBox.W == 0`) yields a non-finite or ≤0 determinant; we clamp the scale to `1` so a stroke
  is never silently zeroed or `NaN`'d.

**Known un-scaled siblings (out of scope — also user-unit lengths):** `Dash` / `DashOffset` are
likewise passed raw and remain unscaled by this patch.

## Modified / added files (must match `tools/verify_oksvg_provenance.go`)

- `svg_path.go` — **MODIFIED** (the stroke-scale patch above).
- `PATCH-NOTES.md` — **ADDED** (this file).

Everything else is byte-identical to `fyne-io/oksvg@v0.2.0`.
