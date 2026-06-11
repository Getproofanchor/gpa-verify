# gpa-verify 1.3.0 — Stamp-6 MHTML binding validation

`gpa-verify` now actively validates the `page.mhtml` offline snapshot that
GetProofAnchor bundles have carried since backend v1.10.0 (server captures)
and extension v1.10.1 (browser captures).

## What changed

Bundles using the `getproofanchor-eidas-stamp-6` payload format bind the
SHA-256 of `page.mhtml` directly under the qualified TSA signature. Verifier
1.2.0 hashed `page.mhtml` as part of `bundle_integrity` (so tampering was
*detectable* via the manifest) but did **not** cross-check it against
`proof.json` or the TSA-signed `eidas_payload.json`. This release adds those
two cross-checks, bringing MHTML to parity with the stamp-5 artifacts (HAR,
video, TLS PEM).

### Added
- `cross_references`: validates `page.mhtml` against `proof.json.mhtml_sha256`
  (sub-check `page_mhtml`).
- `cross_references`: adds `mhtml_sha256 → page.mhtml` to the eidas-payload
  asset map (sub-check `eidas_payload_vs_mhtml_sha256`) — MHTML is now verified
  under the TSA signature, so a post-timestamp swap of `page.mhtml` is
  cryptographically detectable.
- MHTML included in the direct-binding informational note (renamed from
  `stamp5_direct_binding` to `direct_binding` to cover stamp-5 and stamp-6).
- Regression tests: `test_mhtml_verified_when_present`,
  `test_tamper_mhtml_one_byte_detected` (auto-skip on pre-stamp-6 bundles).

### Compatibility
- Pre-stamp-6 bundles (no `page.mhtml`) verify **identically** — the MHTML
  checks are no-ops when `proof.json` declares no `mhtml_sha256`.
- Captures where MHTML failed (graceful degradation; NULL mhtml fields) verify
  identically — no false failures.
- The seven top-level check layers are unchanged. MHTML is a sub-check inside
  `cross_references`, so `checks_total` stays 7.
- Browser captures continue to SKIP `tls_evidence` (no server-side TLS PEM).

## Verify

```bash
pip install --upgrade gpa-verify        # 1.3.0
gpa-verify GetProofAnchor_Evidence_*.zip
```

A stamp-6 bundle will now show `page_mhtml` and `eidas_payload_vs_mhtml_sha256`
among the `cross_references` sub-checks.

## Notes for maintainers
- Test fixtures (real evidence ZIPs) live in `tests/fixtures/` for `git clone`
  + `pytest`, but are excluded from the PyPI sdist to keep the package small
  (sdist ~21 KB, wheel ~18 KB).
- Build: `python -m build`; publish: `twine upload dist/*`.
