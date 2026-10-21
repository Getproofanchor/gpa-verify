# Changelog

## [1.6.0] — 2026-10-21

### Security

- **TSA chain pinned to SK ID Solutions** (new check `tsa_trust_root` for
  SaaS ZIPs, Forensic Browser ZIPs and sealed PDFs). Offline, a self-made TSA
  plus an edited Trusted List bundled in the evidence passed `tsl_qualified`.
  Now the signer certificate must chain to ROOT G1R, ROOT G1E or EE
  Certification Centre Root CA (pinned in `gpa_verify.trust`) through CA
  certificates only (basicConstraints, keyUsage keyCertSign,
  pathLenConstraint — enforced in `build_chain` for every chain), be issued
  directly by the pinned *SK TSA CA 2023R* (older stamps: directly by EE
  Certification Centre Root CA), and carry
  exactly the critical `id-kp-timeStamping` EKU. A certificate issued under
  SK's ID-card or e-seal CAs therefore cannot pass as a TSA. Other TSAs:
  `--trust-root root.pem`.
- **`eidas_signature` (SaaS) uses the same strict RFC 3161 profile as the
  Forensic Browser verifier**: no fallback to the first certificate when the
  SignerInfo matches none, exactly one messageDigest, content-type and ESS
  signing-certificate binding, exact critical timeStamping EKU.
- **PAdES post-seal analysis compares every object with the sealed revision**
  (pre-release review, two rounds). The sealed revision is parsed on its own
  from the sealed bytes, and every object of the final document — as a
  viewer resolves it, object streams included — must equal it or match a
  permitted LTV pattern: a DSS followed only through its defined structure
  (Certs/CRLs/OCSPs/VRI → new streams), new document time-stamps with
  invisible, action-free widgets, and the matching catalog/AcroForm/page
  `/Annots` changes. Rewritten sealed streams (whatever their `/Type`),
  objects not listed in any xref section, an xref chain skipping the sealed
  revision and a replaced `/Root` are reported as modifications.
- **Resource limits for hostile input**: linear signature scan (≤ 64
  signature dictionaries), bounded FlateDecode (64 MB per stream, 256 MB per
  document), validated predictor parameters and xref-stream /W, ZIP member
  and total size limits, compression-ratio limit, duplicate member names
  rejected (`zip_structure`).
- **Removing `timestamp/eidas.tsr` no longer yields VERIFIED** (pre-existing
  since ≤ 1.5.0). A bundle that declares a qualified timestamp
  (`proof.json` `eidas.status == "ok"`/`present`, `manifest.json` `eidas`,
  `status.eidas_ok`, `timestamp/eidas_meta.json` status `ok`, or a manifest
  entry for the token) but lacks the token or the stamped payload now FAILS
  `eidas_signature`, matching the GetProofAnchor online verifier
  (`timestamp_missing`). Bundles of proofs without a qualified timestamp
  (they carry `eidas_payload.json` but declare nothing) keep their verdict.
- **`eidas_signature` now checks the signed `messageDigest` attribute against
  the encapsulated TSTInfo** (RFC 5652 §5.4). A re-encoded TSTInfo with a
  forged message imprint kept a valid signature and passed.
- **The anchor witness is no longer treated as proof of Bitcoin anchoring.**
  `chain/anchor_witness.jsonl` carries `(seq, prev_hash, entry_hash)` only;
  entry hashes cannot be recomputed from the bundle. The last witness `seq`
  must now equal the anchored `seq` (otherwise SKIP with `last_witness_seq` /
  `anchor_seq`), and every result is labelled "informational (not
  independently recomputable)" (`extra.informational = true`,
  `extra.independently_recomputable = false`). No bundle that verified with
  1.5.0 fails because of this change.

### Added

- `anchor_inclusion` check (anchor v3). PASS (`extra.result = "verified"`)
  means exactly: content ↔ eIDAS payload whose qualified timestamp verified in
  `eidas_signature` ↔ leaf
  `SHA256("gpa-anchor-leaf-v3" 0x00 proof_id 0x00 SHA256(timestamp/eidas_payload.json))`
  ↔ RFC 6962 audit path (RFC 9162 §2.1.3.2, bound to `leaf_index` /
  `leaf_count`) ↔ `merkle_root` ↔ v3 anchor payload ↔ the digest in the `.ots`
  receipt header, which must carry at least one attestation. Bitcoin block
  confirmation is a separate result (`extra.bitcoin_verification`).
  Other results: `unverifiable` (SKIP: unparsable / attestation-less receipt,
  or the payload's timestamp did not verify; `extra.reasons`), `not_present`
  (SKIP, older bundles), `failed` (FAIL).
- `--bitcoin-rpc` also verifies the **content anchor's** receipt
  (`anchor/inclusion_anchor_receipt.ots` when the proof is in a later anchor
  than the chain anchor); a failed node check fails `anchor_inclusion`.
- `summary.anchor_inclusion` and `summary.qualified` (`per_supplied_tsl` /
  `not_checked` / `failed`) in the JSON report. Notes and the verdict line no
  longer call a time-stamp qualified unless a Trusted List was checked.
- Public helpers `gpa_verify.core.anchor_leaf_v3` and
  `gpa_verify.core.merkle_root_from_path`.

### Changed

- SaaS ZIPs now run 12 checks instead of 10: `anchor_inclusion` and
  `tsa_trust_root` are appended at the end, so the positions of the 1.5.0
  checks in `checks[]` are unchanged. The JSON schema only gains fields. `anchor_witness` details gained
  an "informational (not independently recomputable): " prefix.
- Hex digests in `anchor/inclusion.json` must be exactly 64 lowercase hex
  characters; invalid `proof_id` values (non-string, > 64 chars, NUL, lone
  surrogates) fail cleanly instead of raising.

### Tests

- `tests/test_anchor_inclusion.py`: RFC 6962 known-answer vectors; path
  tampering; server-generated v3 fixtures with a (non-qualified) test TSA token
  (`tests/fixtures/v3/`, same anchor and later anchor) and ten tampered
  variants; grafted foreign inclusion; garbage and header-only receipts;
  stripped TSR; crafted proof_id; uppercase hex; `--bitcoin-rpc` on the content
  receipt (mocked node); real production bundles with an inclusion proof
  grafted in; the audit's forged-witness PoC; forged TSTInfo; and the
  independent reviewer's 16 adversarial bundles (`tests/fixtures/review/`).
- `test_check_count` updated to 12 checks.
- `tests/test_review_attacks.py`: DSS smuggling, catalog/AcroForm swap,
  chains through non-CA certificates, pathLen, TSA issued by a non-TSA CA,
  ByteRange spam, predictor and Flate bombs, duplicate ZIP members, ZIP bombs.

### Added — Forensic Browser outputs

- Verification of GetProofAnchor **Forensic Browser** (desktop app) outputs,
  auto-detected by `gpa-verify <file>`:
  - **ZIP packages** (`getproofanchor-lite-2`): manifest integrity, binding of
    every sealed file through `timestamp/eidas_payload.json`, multi-page
    sessions (`pages/NN/`), RFC 3161 token, TSA chain, EU Trusted List status
    at genTime, consistency of the producer's time-stamp metadata and report.
    Previously these packages failed with `unsupported format`.
  - **PAdES-sealed PDFs** (document time-stamp, ETSI EN 319 142): ByteRange
    coverage, token over the signed bytes, attachments with SHA-256 vs the
    embedded manifest, and classification of incremental updates after
    sealing (LTV/DSS permitted, anything else reported as modified).
  - **Unsealed plain copies** (`*_bez-pecete.pdf`): identification read from
    the QR code and the printed text; reported as not verifiable by itself,
    or matched against the sealed original with `--original`.
- New CLI options `--original`, `--tsl`, `--certs`; new exit code `3`
  (not verifiable by itself).
- Strict RFC 3161 token verifier (`tsp_verify`): content-type and
  messageDigest attributes, ESS signing-certificate(-v2),
  CMSAlgorithmProtection, critical timeStamping EKU, genTime within the
  certificate validity, chain building with per-link signature checks,
  Trusted List status evaluated with service history.
- Small pure-Python PDF reader (`pdfmini`) and QR-code reader (`qrdecode`) —
  no new dependencies.
- API: `verify_bytes`, `detect_kind`, `verify_fb_zip`, `verify_sealed_pdf`,
  `verify_plain_copy`. `verify_evidence_zip` routes Forensic Browser ZIPs to
  the new verifier.
- docs/forensic-browser-formats.md — the formats as found in real outputs.


## [1.5.0] — 2026-08-03

### Security

- **Certified file digests are now verified.** Versions up to 1.4.0 never
  examined `files_manifest.json` or the preserved bytes under `files/`, so
  file-digest bundles were reported as VERIFIED even when the certified
  SHA-256 had been altered or the retained file contents replaced. Because
  `manifest.json` is not covered by the qualified timestamp, an attacker
  could recompute it freely and defeat the integrity layer. The new
  `file_digest` check anchors every comparison on `capture/capture_meta.json`
  and `content.txt`, which are bound into the eIDAS payload and cannot be
  edited without breaking the TSA signature.

  Anyone who verified a file-digest bundle with 1.4.0 or earlier should
  re-run it with 1.5.0.

### Added

- `file_digest` check — cross-verifies each certified file's digest and size
  against the sealed capture metadata and the sealed content summary, and
  re-hashes retained file contents against the certified digest.
- `anchor_witness` check — walks `chain/anchor_witness.jsonl` from the proof's
  chain entry to the head covered by the OpenTimestamps anchor, so the Bitcoin
  anchor can be tied to the proof offline. Reported as a skip, not a failure,
  when the witness is absent: such bundles are internally consistent and their
  qualified timestamp is unaffected.

### Changed

- Verification now runs 10 layers instead of 8.

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