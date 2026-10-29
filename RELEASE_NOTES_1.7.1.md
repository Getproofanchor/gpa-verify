# gpa-verify 1.7.1 — security release for SaaS evidence ZIPs

An independent audit (2026-10-26) found that the offline verifier was weaker
than the GetProofAnchor online verifier. 1.7.1 closes the gaps. Forensic
Browser verification is unchanged.

## What changes for you

- **`✓ VERIFIED` now requires a verified qualified timestamp.** A package
  without one — whether it never had one or someone removed it together with
  every eIDAS marker — is reported as
  `! INTEGRITY ONLY — no qualified timestamp; the files are only consistent
  with manifest.json, which anyone can recompute`, with **exit code 4**.
  Before, such a package (even with an edited screenshot) could show
  `✓ VERIFIED`.
- **Sealed facts are printed.** For every package whose timestamp verifies
  you now see the proof id, source URL, final URL, capture time, time-stamp
  time and capture mode exactly as sealed, plus the list of sealed files.
  Compare the report with these lines. For a browser-extension capture the
  output says that the content was supplied by the customer's browser and
  sealed on receipt.
- **`proof.json` must agree with the sealed facts.** An edited URL, capture
  time or proof id, or a browser capture relabelled as a server capture,
  now FAILS (`sealed_identity`).
- **Files not listed in `manifest.json` fail the package** (`unlisted_files`),
  as online.
- **What is not sealed is stated:** `report.pdf`, `proof.json`,
  `manifest.json`, `README.md` and the timestamp helper files are generated
  at download time and are not sealed.
- **A SaaS `report.pdf`** is recognised: "This is the unsealed
  human-readable report of a SaaS proof — verify its Evidence ZIP instead".
  `--original <zip>` says whether it is the report shipped in that package.
- The informational anchor witness is shown as `INFO` and no longer counted
  as a passed check.

## Exit codes

| Code | Verdict |
|------|---------|
| 0 | VERIFIED |
| 1 | FAILED |
| 2 | invalid arguments / cannot read input |
| 3 | NOT VERIFIABLE BY ITSELF (unsealed copy or report) |
| 4 | INTEGRITY ONLY (new) |

Scripts that treated "exit code ≠ 1" as success must now also handle 4.

## JSON

Additive: `summary.sealed`, `summary.not_sealed`, `summary.checks_info`,
`summary.notes`; new verdict value `INTEGRITY_ONLY`; new check status
`info`; two new checks appended at the end of `checks`.

## Usage

```bash
pip install --upgrade gpa-verify
gpa-verify GetProofAnchor_Evidence_<proof id>.zip
gpa-verify report.pdf --original GetProofAnchor_Evidence_<proof id>.zip
```
