# Changelog

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
