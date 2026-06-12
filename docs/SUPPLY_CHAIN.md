# Supply-chain runbook

Dependency, build, and signing security for svgsteg. **Fail-closed everywhere:** insufficient
information is a failure, not a pass; a scan that cannot run blocks the merge; an incomplete SBOM
errors loudly. Never accept a false negative.

This document is a spec. The CI in `.github/workflows/renovate-pr-audit.yml` is **inert until pinned**
(every action SHA is a placeholder) — see *Pinning* below.

---

## 0. Principles

- **Fail-closed.** No `continue-on-error`, no `|| true` that swallows a verdict. Tool error, empty
  output, or missing data ⇒ non-zero exit ⇒ blocked PR.
- **Verify, don't assert.** Prove the SBOM equals what's linked; prove the brotli fork equals upstream.
  A version literal is a trust assertion to be checked, not a constant.
- **No single tool is a verdict.** Compose signals; the human approves.
- **Hash-pin everything** — actions by commit SHA, tools by version+checksum, images by digest.
- **Two-sided risk.** Pinning resists fresh-malware/typosquat but accrues known-CVE rot. Watch both.

| Risk | Cause | Control |
|---|---|---|
| Fresh supply-chain attack | bumping to a just-published compromised version | age floor (quarantine) + identity/diff/scanner audit |
| Known-CVE rot | sitting on a pinned old version when a CVE lands | continuous vuln scanning of the *pinned* set |

---

## 1. What Go gives you for free

- **`go.sum`** — cryptographic `h1:` hashes per module, backed by **`sum.golang.org`**, a public
  append-only Merkle transparency log (CT-for-Go-modules). Guarantees **integrity** + **non-equivocation**
  (an author can't serve different bytes to different victims). *Not* safety and *not* provenance.
- **No install scripts.** `go mod download` fetches + hash-verifies *source only* — no npm-style
  `postinstall` RCE. Code runs only at **build (cgo), `go generate`, or test**.
- **`govulncheck`** — reachability-aware CVE scan (in `tools/releasegate.go`); covers stdlib + toolchain.
- **`CGO_ENABLED=0`** (our build) — no C blind spot; govulncheck reachability is near-total.

**Our one carve-out:** the brotli `replace => ./third_party/brotli` leaves the proxy/checksum-DB path,
so it is **outside `sum.golang.org`**. `tools/verify_brotli_provenance.go` is the compensating control —
it proves byte-identity to upstream `v1.2.1` (minus `http.go`). See §5.

---

## 2. The two diffs (run on every dependency PR)

Point-in-time scans answer "does HEAD have vulns." The useful question is the **delta**.

### 2a. CVE-posture diff
Run `osv-scanner` + `govulncheck` on **base** and **head**, diff the sets:
`fixed = base−head`, `introduced = head−base`, `net = better|worse|equal`.
- `govulncheck` = curated Go DB + reachability → "**exploitable now**".
- `osv-scanner` = full OSV + presence → "**present — audit reachability**".
- Run both; neither alone is complete. **`introduced ≠ ∅` blocks** absent an explicit reviewed override.

### 2b. Capability diff (the malware check that works for source)
`capslock` reports each dependency's capabilities. A dep that never touched `network` suddenly
acquiring it **is** the exfil-backdoor signature — deterministic and obfuscation-proof (a backdoor that
phones home *must* acquire the capability). Diff head vs a committed `.capslock-baseline.json`.
**A new `CAPABILITY_NETWORK` / `_RUNTIME`(exec) / `_UNSAFE_POINTER` / `_FILES` blocks**, pending the ritual in §3.

---

## 3. Capability-decision ritual (the brotli template)

A capability flag is a prompt to investigate and **record a durable decision** — the `http.go` story:

1. **Detect** — capslock diff flags a new capability.
2. **Trace** — `capslock -output=v` prints the call path → the exact file/function that acquires it.
3. **Decide** — accept · **vendor-and-strip** (the `http.go` move) · reject · hold-old.
4. **Prove** — byte-identity to upstream (the `verify_brotli_provenance.go` pattern).
5. **Record** — append to `CAPABILITY_DECISIONS.md`: module, version, capability, source path, decision, rationale.

Worked example (seed entry):

```
github.com/andybalholm/brotli  v1.2.1
  capability:  CAPABILITY_NETWORK  (net/http)
  source:      http.go (brotli HTTP helpers — not used by the encoder)
  decision:    vendor-and-strip — removed http.go via replace => ./third_party/brotli
  proof:       tools/verify_brotli_provenance.go (92 files byte-identical vs upstream; net symbols = 0)
  rationale:   eliminate the only net-capability path; offline tool requires net=0.
```

---

## 4. SBOM completeness — prove it, don't assume it

Generating an SBOM from `go.mod` (declared) misses the build graph (linked). **Reconcile against ground truth:**

- **Generate from the build graph:** `cyclonedx-gomod app -main . -std` (`app` = actually compiled;
  `-std` = stdlib + toolchain component — the most-missed piece).
- **Ground-truth oracle:** `go version -m <binary>` reads the module set **embedded in the binary**.
- **Completeness gate (fail-closed):** assert `SBOM components ⊇ go version -m` set. Any linked module
  absent from the SBOM ⇒ `::error::` + non-zero exit. Empty SBOM ⇒ fail.

This makes "no blind spots" a gate check, not a footnote.

---

## 5. Scanner blind spots (and how we close them)

- **The `replace` gap.** Both scanners key on `PURL@version`; the local brotli fork has no version,
  so a CVE against `brotli v1.2.1` would **not** flag. Fix: (a) annotate the SBOM component with the
  upstream PURL `pkg:golang/github.com/andybalholm/brotli@v1.2.1`; (b) scan upstream `v1.2.1` against
  OSV on a schedule; (c) `verify_brotli_provenance.go` proves the fork == that version.
- **govulncheck reachability gaps:** reflection / `go:linkname` / assembly / cgo can hide a reachable
  vuln. (cgo gap is closed by `CGO_ENABLED=0`.) Mitigate with osv-scanner's presence net.
- **Always scan code AND the binary:** `govulncheck` source mode (reachability) **and**
  `govulncheck -mode binary <bin>` (what's actually linked, incl. the replace's code).
- **Curated-DB narrowness:** `govulncheck` uses `vuln.go.dev` (a Go-triaged subset of OSV) — osv-scanner
  covers the broader OSV.

---

## 6. The two Google services

- **`sum.golang.org`** — integrity/non-equivocation **guarantee** (cryptographic, automatic). Answers
  "are these the real, globally-consistent, untampered bytes?" Not safety, not provenance.
- **`deps.dev` (Open Source Insights)** — posture **signal** (advisory). Per `package@version`: OSV
  vulns, transitive graph, licenses, **OpenSSF Scorecard** (hygiene 0–10), provenance where present.
  Query it on each PR to inform approve/strip/reject. A high Scorecard ≠ safe (a compromised maintainer
  of a well-run repo is the Trivy/Aqua-2026 scenario) — signal, not verdict.

---

## 7. Evidence locker — attestations, SBOM, SLSA L3, in-toto, Rekor

Produce **signed, transparency-logged, verifiable attestations**, not logs. Target **SLSA Build L3**.

Per release, attach (each an **in-toto** Statement, **keyless-signed** via Sigstore **Fulcio**, logged in **Rekor**):

- **SBOM** — `cyclonedx-gomod app -main . -std` + the §4 completeness proof; attested
  (`cosign attest --type cyclonedx` or `actions/attest-sbom`).
- **SLSA Build L3 provenance** — generated by the **`slsa-framework/slsa-github-generator`** Go builder
  (reusable workflow). L3 ⇒ provenance is produced in an **isolated builder job the build steps cannot
  influence**, signed by the workflow's own identity (non-falsifiable). Expressed as an in-toto SLSA
  Provenance predicate.
- **The two diffs** (CVE-posture, capability) + **`deps.dev`/Scorecard** snapshots, attached as evidence.
- **Reproducible-build** proof (byte-identical twin — `releasegate.go`).
- **Decision records** — `CAPABILITY_DECISIONS.md` + PR approvals.

**Signing model (keyless, no key to steal):** Fulcio issues a short-lived cert bound to the CI **OIDC**
identity → `cosign` (artifacts) / `gitsign` (commits) sign → signature + cert are recorded in **Rekor**
(append-only transparency log).

**Verification — fail-closed:** `slsa-verifier verify-artifact` (checks the L3 builder identity + source
repo), `cosign verify-attestation` / `verify-blob` (signature + Rekor inclusion), `gh attestation verify`.
**Pin the expected builder identity + source repo**; missing, unsigned, or mismatched provenance is a
hard failure — never a pass.

---

## 8. Watch-list hardening (collateral beyond the modules)

| Vector | Hardening |
|---|---|
| **GitHub Actions** (`uses:` is executable) | **Pin to full commit SHA, never tags** (the literal Trivy-2026 vector — 76/77 tags force-pushed). Keep a `# vX.Y` comment so Renovate updates the SHA. Default `permissions: read-all`, grant per-job. `persist-credentials: false`. Consider StepSecurity Harden-Runner (egress filtering). |
| **`//go:generate`** | Never run on untrusted code; review directives in deps; don't run on fork PRs; keep generated code committed + reviewed. |
| **cgo / toolchain** | `CGO_ENABLED=0` (done); `GOTOOLCHAIN=local` (no surprise compiler downloads); `GOFLAGS=-mod=vendor`; pin the Go version exactly in CI. |
| **Makefiles / scripts** | Review; no `curl \| sh`; least privilege. |
| **IDE configs** (`.vscode`, `.idea`) | Ignored by the dot-dir net; never auto-run tasks from untrusted clones. |
| **Git hooks** | Bare `.git/hooks` isn't shared by clone (inert). Committed hooks (`core.hooksPath`→`.githooks/`) are **high-trust code that runs with full local privileges** — review like production, keep tiny, pin what they call. A global `core.hooksPath` means *your* hooks always run regardless of a repo's. **Don't detonate others':** the real paths are `go generate`/`make`/CI/`husky prepare` — **inspect before executing anything in an untrusted clone**; clone with `--no-recurse-submodules` unless needed. |

---

## 9. Build & commit signing — remove the long-lived-key attack surface

The whole point: **there must be no long-lived signing key on a machine that also pulls dependencies**
(that machine is the malware target). Move signing to ephemeral, identity-bound contexts.

- **Commit/tag signing — keyless (preferred):** **Sigstore `gitsign`** — ephemeral keys tied to your
  OIDC identity, logged in the Rekor transparency log; nothing to steal. Alternative: a **hardware key**
  (YubiKey, non-exportable, touch-to-sign). Enforce via branch protection: **require signed commits**.
- **Release/artifact signing — in the runner, not the laptop:** **`cosign` keyless** (Sigstore, CI OIDC,
  Rekor-logged) + **SLSA Build L3 provenance** via the isolated `slsa-github-generator` (§7). The
  short-lived OIDC token signs and expires; no stored secret.
- **Lock down the surface:**
  - **No long-lived keys / PATs.** Keyless (OIDC) or HSM only; CI uses OIDC, not stored secrets.
  - **Branch protection:** require signed commits + review + passing checks; **block force-push.**
  - **Tag protection / immutable tags:** prevents the force-push-tags attack; combined with SHA-pinning
    you're immune even if an upstream tag is moved.
  - **Restricted release path:** a GitHub **Environment with required reviewers** (two-person) for the
    sign/publish step.
  - **Reproducible builds** → the signed artifact is independently re-derivable; a tampered build is detectable.

---

## 10. Renovate config (surfacing, not approving)

- `minimumReleaseAge` ≥ a 2–3 day floor (quarantine; the age signal Dependabot lacks).
- `vulnerabilityAlerts` **fast-tracked** (patch known CVEs promptly) vs routine bumps **quarantined**.
- SHA-pin actions; `lockFileMaintenance` + `postUpdateOptions: [gomodTidy]`.
- **Never `automerge`.** Renovate opens a hash-updated PR; the audit (§2–§7) + human approve it.

---

## 11. Pinning procedure (how to get verified SHAs)

The workflow's `@REPLACE_SHA` placeholders must be replaced with **verified** commit SHAs. Each pin
clears four gates (this is what was applied 2026-06-11; see T-057):

1. **Two independent protocols, required to agree.** Resolve the tag → commit SHA two ways and confirm
   they match: `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha` **and**
   `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>^{}` (the `^{}` dereferences an
   annotated tag to its commit; fall back to `refs/tags/<tag>` for lightweight tags). A mismatch is a
   hard stop — do not pin on a single source.
2. **Signature.** Check `gh api repos/<owner>/<repo>/commits/<sha> --jq .commit.verification.verified`.
   Prefer `verified=true`. *Documented exception:* `slsa-framework/slsa-github-generator` commits are
   `unsigned` upstream — this is intrinsic to its trust model (the trusted-reusable-workflow verifies its
   own ref at runtime via OIDC and refuses to emit provenance unless invoked from an official semver
   release tag), not an anomaly. Accepted under compensating controls: two-protocol SHA agreement + an
   official non-prerelease release tag + the runtime TRW check. Re-evaluate if any of those change.
3. **Age ≥ 48 h** (lagging-indicator window for advisories / community signal).
4. **Trailing `# vX.Y.Z` comment** so Renovate can bump the SHA while you re-verify (and so `pingate`
   reads cleanly). `tools/pingate.go` then enforces fail-closed that every `uses:` is a 40-hex SHA.

- Auto-pin alternative (itself vetted + pinned): `pinact`, `ratchet`, or StepSecurity.
- Pin installed scanners by version **and** verify checksum; install them under the
  *bootstrapping-security-tools* protocol (isolated, multi-root verification, quarantine) — the scanner
  stack gets **stricter** scrutiny, not looser.

---

## 12. Adoption gate

Nothing here is active until: actions pinned (§11 — **done 2026-06-11, T-057**), scanners bootstrapped
(four `@PIN_VERSION` installs still open), the CVE-diff + capability-diff comparators implemented (they
are STUBS that `exit 1`), Renovate enabled, branch/tag protection + signing configured. Adopting it is
itself a supply-chain decision — run the protocol on it.

**Caution — these are not inert.** Both `release-provenance.yml` (`on: release`) and `renovate-pr-audit.yml`
(`on: pull_request`) are committed with live triggers, so they will FAIL on the first matching event until
the remaining items land. Neutralize the triggers (→ `workflow_dispatch:` only) before the first push/PR,
or finish the scanner bootstrap + comparators first.
