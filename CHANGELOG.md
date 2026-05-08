# Changelog

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