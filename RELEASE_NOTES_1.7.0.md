# gpa-verify 1.7.0 — Forensic Browser "Files and documents"

Forensic Browser 1.5.0 adds a second kind of evidence next to web pages:
**sealing files**. The operator selects one or more files — from the
computer, downloaded from a URL in the browser session (with every redirect
recorded), or from the browser's Downloads panel — and the app seals them
into one evidence with one qualified time-stamp, as a ZIP package, a
PAdES-sealed PDF, or a sealed PDF plus an unsealed plain copy.

gpa-verify 1.7.0 verifies all three.

## What a VERIFIED verdict proves

That **exactly these bytes** existed at the time of the time-stamp and have
not changed since: each file's SHA-256 and SHA-512 and size match
`proof.json`, the file and its provenance record `files/NN/source.json` are
bound to the time-stamp, and nothing undeclared was added. It does **not**
prove who created a file or that its content is true. Times taken from the
operator's file system are recorded as operator-supplied and are not
verifiable; a file downloaded from a URL is what that server delivered to
the operator's browser session at that time.

## New and changed checks

- `files` (ZIP): per file SHA-256, SHA-512, size, sealed binding of the file
  and of `source.json`, agreement of `source.json` with `proof.json`
  (index, name, hashes, size, source type), `source_json_sha256`,
  `file_count`, `total_size`, `capture_meta.kind`/`file_count`, safe file
  names, unique indices, no undeclared files under `files/`.
- `evidence_consistency` (sealed PDF): the same against the embedded
  attachments, plus "printed SHA-256 values match attachments".
- `copy_content_consistency` (plain copy with `--original`): URLs printed on
  the copy must be the request, redirect, final or download URLs recorded in
  the original.
- Dispatch: SaaS bundles (`getproofanchor-evidence-N`, including
  file-digest proofs with `files_manifest.json`) and Forensic Browser files
  packages cannot be mistaken for each other.

Verification of web-capture outputs (`getproofanchor-lite-2`) is unchanged.

## Usage

```bash
gpa-verify GetProofAnchor_sess-1792600000000.zip
gpa-verify GetProofAnchor_sess-1792600000000.pdf --tsl EE.xml
gpa-verify GetProofAnchor_sess-1792600000000_bez-pecete.pdf \
           --original GetProofAnchor_sess-1792600000000.pdf
```
