# Changelog

## 1.3.0 (2026-06-10)

**Stamp-6 MHTML snapshot binding validation**

Production bundles emitted since backend v1.10.0 (server captures) and
extension v1.10.1 (browser captures) include a `page.mhtml` offline
snapshot whose SHA-256 is bound directly into the eIDAS stamp-6 payload
(`getproofanchor-eidas-stamp-6`). Verifier 1.2.0 verified such bundles
as a whole (the `page.mhtml` file was hashed by `bundle_integrity` like
any other manifest entry) but did NOT cross-check `page.mhtml` against
the TSA-signed `eidas_payload.json` or against `proof.json`. MHTML was
therefore covered by the manifest but not by the strongest "trust only
what was timestamped" check.

This release closes that gap: `page.mhtml` is now validated the same way
stamp-5 artifacts (HAR, video, TLS PEM) are — its hash must match both
`proof.json` (`mhtml_sha256`) and the TSA-signed eidas payload. Swapping
`page.mhtml` after timestamping is now cryptographically detectable.

### Added
- `cross_references` checks `page.mhtml` against `proof.json.mhtml_sha256`
  (new sub-check `page_mhtml`).
- `cross_references` adds `mhtml_sha256 -> page.mhtml` to the eidas-payload
  asset map (new sub-check `eidas_payload_vs_mhtml_sha256`), so MHTML is
  verified under the TSA signature.
- MHTML included in the direct-binding informational note (renamed from
  `stamp5_direct_binding` to `direct_binding` to cover stamp-5 and stamp-6).
- Test fixtures: real stamp-6 server and browser evidence bundles.
- Regression tests: `test_mhtml_verified_when_present`,
  `test_tamper_mhtml_one_byte_detected` (auto-skip on pre-stamp-6 bundles).

### Compatibility
- Pre-stamp-6 bundles (no `page.mhtml`) verify identically — the MHTML
  checks are no-ops when `proof.json` declares no `mhtml_sha256`.
- Captures where MHTML failed (graceful degradation, NULL mhtml fields)
  verify identically — no false failures.
- The seven top-level check layers are unchanged; MHTML is a sub-check
  within `cross_references`, so `checks_total` stays 7.
- Browser captures continue to SKIP `tls_evidence` (no server-side TLS PEM).

## 1.2.0 (2026-05-14)

**Accept evidence-3 and evidence-4 bundle formats**

Production GetProofAnchor bundles emitted since backend M-6b are
formatted as `getproofanchor-evidence-4` (per-country TSL bundles
included in `timestamp/tsl/<COUNTRY>.xml`). Verifier v1.1.0 rejected
all such bundles at `check_bundle_integrity` with
`unsupported format: getproofanchor-evidence-4`.

This release accepts evidence-3 and evidence-4 without changes to
verification logic — all seven cryptographic checks operate
identically on the new manifest format (file dict with `sha256`
and `size` per entry). The change is purely a relaxation of the
format gate.

### Added
- `getproofanchor-evidence-3` to `SUPPORTED_FORMATS`
- `getproofanchor-evidence-4` to `SUPPORTED_FORMATS`

### Compatibility
- All evidence-1 and evidence-2 archives continue to verify identically
- All stamp-3, stamp-4, stamp-5 eIDAS payloads continue to verify identically
- No changes to check semantics — same input still produces same output
  on archives already supported in 1.1.0

## 1.1.0 (2026-05-07)

**Stamp-5 forensic asset binding validation**

Adds new cross-check that validates, for stamp-5 archives, that
each declared asset hash in eidas_payload.json matches the actual
file in the archive. This makes it cryptographically impossible to
swap any forensic artifact (HAR, video, TLS PEM) post-timestamping
without the verifier detecting it.

### Added
- cross_references reads timestamp/eidas_payload.json and validates
  each declared artifact hash against the matching file
- New check entries: eidas_payload_format, stamp5_direct_binding
- 14 cross-checks on full stamp-5 server proof (was 4)

### Compatibility
- All stamp-3 and stamp-4 archives verify identically
- Forward-compatible with backend v1.8.8 stamp-5 emission


## 1.1.0 (2026-05-07)

**Stamp-5 forensic asset binding validation**

Adds new cross-check that validates, for stamp-5 archives, that
each declared asset hash in eidas_payload.json matches the actual
file in the archive. This makes it cryptographically impossible to
swap any forensic artifact (HAR, video, TLS PEM) post-timestamping
without the verifier detecting it.

### Added
- cross_references reads timestamp/eidas_payload.json and validates
  each declared artifact hash against the matching file
- New check entries: eidas_payload_format, stamp5_direct_binding
- 14 cross-checks on full stamp-5 server proof (was 4)

### Compatibility
- All stamp-3 and stamp-4 archives verify identically
- Forward-compatible with backend v1.8.8 stamp-5 emission


All notable changes to `gpa-verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-05-07

### Added
* Initial release.
* Seven-layer offline verification:
  bundle integrity, cross-references, chain integrity, eIDAS RFC3161
  signature (with timeStamping EKU enforcement), anchor canonical hash,
  OpenTimestamps receipt structure, TLS evidence consistency.
* Pretty CLI output with colour and JSON output for automation.
* Support for evidence bundle formats `getproofanchor-evidence-1` and
  `getproofanchor-evidence-2`.
* Pure-Python — no native dependencies, no GetProofAnchor servers.

[1.0.0]: https://github.com/getproofanchor/gpa-verify/releases/tag/v1.0.0