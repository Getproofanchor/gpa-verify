# Forensic Browser output formats (as found)

Reverse-documented on 2026-10-21 from real outputs of the GetProofAnchor
Forensic Browser desktop app (`gpa-forensic-browser-1.4.3` / `1.4.4`, Electron
44 / Chromium 152), using `asn1crypto`, `cryptography`, `qpdf`, `pdfinfo`,
`pdftotext` and `pdfimages`. Everything below is what the files actually
contain, not a specification from the producer. Where this document says
"sealed" it means "covered by the qualified electronic time-stamp".

The app produces three kinds of output per session (`sess-<epoch-ms>`):

| Output | File name | Seal |
|---|---|---|
| ZIP package | `GetProofAnchor_sess-<id>.zip` | RFC 3161 token over `timestamp/eidas_payload.json` |
| Sealed PDF | `GetProofAnchor_sess-<id>.pdf` | PAdES document time-stamp (ETSI EN 319 142-1, `/ETSI.RFC3161`) over the whole file |
| Plain copy | `GetProofAnchor_sess-<id>_bez-pecete.pdf` | **none** — identifies the sealed PDF by SHA-256 |

All observed time-stamps come from **SK ID Solutions AS**, TSU certificate
`SK TIMESTAMPING UNIT 2026R` (issuer `SK TSA CA 2023R` → root
`SK ID Solutions ROOT G1R`), policy `0.4.0.2023.1.1` (ETSI best-practice
TSA policy), accuracy 1 s, with nonce. The TSU certificate is listed as a
granted `TSA/QTST` service in the Estonian Trusted List.

---

## 1. ZIP package — `manifest.format = "getproofanchor-lite-2"`

Deflate-compressed ZIP, flat paths:

```
capture/capture_meta.json        sealed   capture metadata (tool versions, host, per-page steps,
                                          TLS/IP of the main document, screenshot geometry)
capture/capture_meta.sha256      sealed   "<sha256>  capture_meta.json\n"
network/capture.har              sealed   HAR 1.2 (headers/timings, no bodies)
network/dns.json                 sealed   {url: {hostname, addresses[]}}
pages/NN/page.html               sealed   DOM outerHTML           (NN = 01, 02, … one dir per page)
pages/NN/screenshot.png          sealed   full-page screenshot
pages/NN/page.mhtml              sealed   optional (include_mhtml)
media/session.mp4                sealed   optional (include_video)
proof.json                       sealed   session summary + per-page hashes
timestamp/eidas_payload.json     -        THE time-stamped document (see below)
timestamp/eidas_payload.sha256   -        "<sha256>  eidas_payload.json\n"
timestamp/eidas.tsr              -        RFC 3161 TimeStampResp (status granted + token)
timestamp/eidas_meta.json        -        {gen_time, hash_algo, payload_sha256, policy_oid, serial, tsa_name}
timestamp/eidas_verification_report.json  producer's own verification summary
timestamp/qualified_context.json -        TSL provenance: LOTL URL+sha256, member-state TSL URL+sha256,
                                          bundled file, status ("ok"/"cache"/…)
timestamp/tsa_certs.pem          -        TSU + issuing CA + root (3 certs)
timestamp/tsa_signer_cert.pem    -        TSU certificate
timestamp/tsl/EE.xml             -        member-state Trusted List snapshot (ETSI TS 119 612)
report.pdf                       -        human-readable report (ReportLab, NOT sealed)
manifest.json                    -        not listed in itself
```

`manifest.json`:

```json
{"files": {"<path>": {"sealed": true|false, "sha256": "…", "size": N}, …},
 "format": "getproofanchor-lite-2", "generated_at": "…Z",
 "integrity": {"note": "…", "sealed_count": 7, "sealed_payload_file": "timestamp/eidas_payload.json",
               "unsealed_count": 10},
 "payload_sha256": "<sha256 of eidas_payload.json>", "session_id": "sess-…"}
```

`timestamp/eidas_payload.json` — canonical JSON (sorted keys, no spaces,
UTF-8; the bytes on disk are exactly `json.dumps(obj, sort_keys=True,
separators=(",", ":"), ensure_ascii=False)`):

```json
{"files": {"capture/capture_meta.json": "<sha256>", "capture/capture_meta.sha256": "<sha256>",
           "network/capture.har": "<sha256>", "network/dns.json": "<sha256>",
           "pages/01/page.html": "<sha256>", "pages/01/screenshot.png": "<sha256>",
           "proof.json": "<sha256>"},
 "finished_at": "…Z", "format": "getproofanchor-lite-2",
 "operator_username": "licence:GPA-…", "session_id": "sess-…"}
```

The TSR `messageImprint` is `SHA-256(eidas_payload.json bytes)`. The
payload's `files` map is exactly the set of `sealed: true` files in the
manifest. So the trust chain is: TSA signature → TSTInfo → imprint →
payload bytes → per-file SHA-256 → file bytes.

`proof.json`: `{app_version, capture_meta_sha256, finished_at, format,
include_mhtml, include_video, operator{name, username}, page_count,
pages[{captured_at, index, page_html_sha256, screenshot_sha256,
[mhtml_sha256], title, url}], session_id, started_at}`.

Token details: `TimeStampResp` → `SignedData` v3, digest SHA-512,
`sha512WithRSAEncryption` (RSA 4096), signed attributes `content-type`,
`signing-time`, `CMSAlgorithmProtection`, `message-digest`,
`signing-certificate-v2`; only the TSU certificate is embedded in the token
(the chain is in `tsa_certs.pem`).

Differences from the SaaS evidence bundle (`getproofanchor-evidence-N`):
no hash chain (`chain/`), no OpenTimestamps anchor, no `content.txt`, no
`tls/` PEMs; per-page directories instead of a single `screenshot.png`; an
explicit sealed/unsealed split in the manifest. gpa-verify ≤ 1.5.0 reported
`unsupported format: getproofanchor-lite-2` and `chain/proof_chain.jsonl
missing` (FAILED) even though the token and TSL checks passed — and its
cross-reference layer never checked the payload's `files` map.

## 2. Sealed PDF — PAdES document time-stamp

Produced by ReportLab (report), rewritten by `pypdf` (attachments added),
time-stamped by `pyHanko 0.36.2`.

* Header `%PDF-1.4`, catalog `/Version /1.7`,
  `/Extensions << /ESIC << /BaseVersion /1.7 /ExtensionLevel 1 >> >>`.
* Classic cross-reference tables, no object streams, **two revisions**:
  1. the report plus attachments (`/Names /EmbeddedFiles` name tree and
     catalog `/AF` array, each file spec with `/AFRelationship /Supplement`
     and a Czech `/Desc` that starts with the original package path, e.g.
     `"capture/capture_meta.json — artefakt důkazního balíčku"`);
  2. the time-stamp increment: updated Info (`/Producer`, `/ModDate`),
     catalog (`/AcroForm`), page 1 (`/Annots`), an invisible signature
     field/widget (`/FT /Sig`, `/Rect [0 0 0 0]`, `/T (Timestamp-<uuid>)`)
     and the signature value dictionary
     `<< /Contents <…> /ByteRange [0 a b c] /Type /DocTimeStamp
     /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 >>`.
* `/ByteRange` covers the whole file except the `<…>` hex string of
  `/Contents` (the gap starts at `<` and ends after `>`); `b + c` equals the
  file length, i.e. nothing follows the time-stamp revision. `/Contents`
  holds a bare `TimeStampToken` (ContentInfo/SignedData, same profile as in
  the ZIP) followed by ~1.6 kB of zero padding.
* `messageImprint` = SHA-256 of the two signed ranges concatenated.
* **No DSS / VRI** (no LTV material), no CRLs/OCSP, and the token embeds
  only the TSU certificate — the issuing CA and the Trusted List are not in
  the PDF.
* Attachments are uncompressed `/EmbeddedFile` streams with `/Subtype` =
  MIME type and `/Length`; no `/Params /Size /CheckSum`. Names are the
  package path with `/` → `_` (`pages_01_screenshot.png`); `page.mhtml` is
  stored as `pages_01_page.mhtml.txt` (MIME `multipart/related`).
* The embedded `manifest.json` has `"container": "pdf"`, the same
  `files{path: {sealed, sha256, size}}` map (all `sealed: true`), `format`,
  `generated_at`, `session_id`, and a note that the PAdES time-stamp covers
  the whole PDF. There is no `eidas_payload.json` in the PDF — the document
  time-stamp replaces it.
* The visible report lists every attachment with size and SHA-256, and the
  session id ("ID relace").
* The Info dictionary was reduced by `pypdf` to `/Producer` + `/ModDate`
  (the ReportLab `/Title`, `/Creator`, `/Author` are lost). No XMP.

## 3. Plain copy — `*_bez-pecete.pdf` (unsealed)

Plain ReportLab PDF, single revision, no signature, no attachments, for
import into systems (e.g. the Czech police case system KOPR) that strip
PAdES seals. Info `/Title "Forenzní záznam o pořízení důkazu — sess-<id>"`,
`/Creator "GetProofAnchor Forensic Browser"`, empty `/Keywords`.

It identifies the sealed original in two places:

* **QR code** on page 1 — a 244×244 px FlateDecode RGB image XObject,
  content is plain JSON (not base64):

  ```json
  {"f":"GetProofAnchor_sess-<id>.pdf","sha256":"<sha256 of the sealed PDF>",
   "sid":"sess-<id>","t":"getproofanchor-plain-copy",
   "ts_serial":"<TSTInfo serialNumber, decimal>","ts_time":"YYYY-MM-DD HH:MM:SS UTC","v":1}
  ```

* **Printed text** ("Orazítkovaný originál tohoto protokolu"): file name,
  SHA-256, size in bytes, QTSP name, time-stamp time and serial — the same
  values as the QR, plus the size. ASCII is emitted as-is; Czech letters use
  TrueType-subset codes with a `/ToUnicode` CMap.

`ts_time` equals the sealed PDF's `genTime` (to the second) and `ts_serial`
its TSTInfo serial. The copy's screenshot preview is a reduced JPEG; the
screenshot SHA-256 it prints refers to the original PNG in the sealed PDF.

## 4. What gpa-verify checks per format

| Format | Checks |
|---|---|
| ZIP | `fb_package` (format, session ids agree) · `bundle_integrity` (SHA-256 + size of every file vs manifest, no undeclared files, counts, `payload_sha256`) · `sealed_binding` (every payload hash = file, payload set = manifest sealed set, payload metadata = proof.json, sidecars) · `pages` (per page dir: screenshot/html/mhtml hashes = proof.json and sealed; no stray page dirs) · `timestamp_token` · `tsa_chain` · `tsl_qualified` (bundled TSL, status at genTime) · `timestamp_metadata` (eidas_meta / verification report / qualified_context agree with token and TSL file) · `report_pdf` (report cites session, payload hash, serial) |
| Sealed PDF | `pdf_structure` · `pades_signature` (ByteRange starts at 0, gap is exactly this dict's `/Contents` hex string, ends at a revision boundary, padding is zeros, field in AcroForm) · `timestamp_token` (imprint = hash of ByteRange data) · `tsa_chain` · `tsl_qualified` (needs `--tsl`) · `post_seal_changes` (later revisions only DSS/VRI/doc-time-stamps, otherwise "MODIFIED AFTER SEALING" with object list and the sealed revision's length + SHA-256) · `attachments` (all embedded files, SHA-256, inside sealed range, vs embedded manifest) · `evidence_consistency` (proof.json ↔ attachments, printed hashes ↔ attachments) |
| Plain copy | `copy_identification` (QR via built-in pure-Python QR reader + printed text, must agree) · `copy_integrity` = SKIP → verdict `NOT_VERIFIABLE` (exit 3). With `--original`: all sealed-PDF checks as `original.*` + `copy_binding` (SHA-256, size, session, serial, time) + `copy_content_consistency` (hashes/URLs printed on the copy exist in the original) |

`timestamp_token` (shared by ZIP and PDF) verifies: status granted,
eContentType id-ct-TSTInfo, imprint, signed attributes `content-type`,
`message-digest` (= digest of the TSTInfo — this binds the signature to
the TSTInfo), ESS `signing-certificate(-v2)`, `CMSAlgorithmProtection`,
the CMS signature (RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA), EKU exactly
id-kp-timeStamping and critical, genTime within the TSU validity.
`tsl_qualified` evaluates the service status **at genTime** using
`ServiceHistory`.

## 5. Known limitations

* The Trusted List snapshot is not authenticated (its XMLDSig signature
  and the LOTL pointer are not verified); its SHA-256 is reported. In the
  ZIP it is unsealed (written after the time-stamp).
* No revocation checking (no OCSP/CRL in either container).
* The plain copy proves nothing by itself; with the original it only proves
  that its *identification data* (and the hashes/URLs it prints) refer to
  that sealed original — not that its pages are a faithful rendering.
