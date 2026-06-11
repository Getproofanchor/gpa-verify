# Changelog

## 1.4.0 (2026-06-11)

### Added — two new verification capabilities

**Layer 8: `tsl_qualified` — EU Trusted List qualified-status check (offline).**
Previously the tool proved the RFC3161 token was signed by the cert embedded
in it and that the cert carried the timeStamping EKU — but it did *not* prove
that cert is a *qualified* TSU recognised by an EU member state. A self-issued
cert can also carry a timeStamping EKU. This layer closes that gap: it parses
the EU Trusted List bundled in the evidence ZIP (`timestamp/tsl/<CC>.xml`,
ETSI TS 119 612) and confirms the signer certificate is listed under a service
that is BOTH type `TSA/QTST` (Qualified Time Stamp) AND status `granted`.
Fully offline, no network. Skips cleanly (not fails) on older bundles that
predate per-country TSL bundling.

**`--bitcoin-rpc URL`: real Bitcoin block verification (opt-in, online).**
By default the OTS layer stays fully offline and reports Bitcoin status from
the manifest only (an assertion by the producer). With `--bitcoin-rpc`
pointing at a Bitcoin Core node **you operate**, the tool now performs REAL
verification: it reads the receipt's `BitcoinBlockHeaderAttestation`,
fetches the attested block's header via `getblockhash`/`getblockheader`, and
confirms the OTS-committed merkle root equals the block header's merkleroot
using the canonical `opentimestamps` library. No calendars, no block
explorers — the only network call is to your own node. The receipt is read,
never upgraded or modified. If the receipt has no Bitcoin attestation yet
(still pending across calendars), online mode says so honestly rather than
claiming "confirmed".

### Changed
- Verification layers: 7 → 8 (`tsl_qualified` inserted after `eidas_signature`).
- `verify_evidence_zip(zip_bytes, *, bitcoin_rpc=None)` — new keyword-only arg.
  The default call is unchanged and remains a pure offline function.
- Module docstring and layer numbering updated.

### Dependencies
- New optional extra `bitcoin` (pulls `opentimestamps`). Install with
  `pip install gpa-verify[bitcoin]` only if you want `--bitcoin-rpc`. The core
  offline verifier still needs only `asn1crypto` + `cryptography`.

### Tests
- `test_check_count` updated to 8 layers.
- Added `test_tsl_qualified_when_present` (passes on bundles with a TSL,
  skips otherwise) and `test_tamper_tsl_cert_swap_detected` (gutting the
  bundled TSL's certs makes `tsl_qualified` fail).
- Bitcoin merkle-verification logic proven with the real `opentimestamps`
  library against a mocked node (correct root verifies; wrong root rejected).

### Notes / honest limitations
- `tsl_qualified` validates against the TSL *bundled in the evidence* and
  reflects status as of that snapshot. It does not (yet) validate the TSL's
  own XML signature against the EU List-of-Lists (LOTL) trust anchor — that
  is a heavier separate step on the roadmap.
- Offline mode still cannot confirm Bitcoin block inclusion (by design); use
  `--bitcoin-rpc` for that.

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