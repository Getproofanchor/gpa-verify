# gpa-verify

**Independent verifier for GetProofAnchor evidence bundles.**

Reads only the bundled ZIP — no network requests, no GetProofAnchor
servers contacted at any point during verification. Same input → same
verdict on every machine.

[![CI](https://github.com/Getproofanchor/gpa-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/Getproofanchor/gpa-verify/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/gpa-verify.svg)](https://pypi.org/project/gpa-verify/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why does this exist?

A GetProofAnchor evidence bundle is a `.zip` containing a screenshot,
HTML, HAR, video, TLS chain, eIDAS qualified timestamp, OpenTimestamps
Bitcoin anchor, and an append-only hash chain. The bundle claims:

> *This URL existed in this exact form at this exact time.*

For court use, the cryptographic part of that claim must be
**independently verifiable** — a forensic expert appointed by a court
should be able to confirm or deny it without relying on the
GetProofAnchor service.

`gpa-verify` is the reference implementation of that verification
protocol. It runs offline, contacts no external services at runtime,
and produces a deterministic verdict.

## Scope of verification

This tool verifies the **cryptographic seals** on an evidence bundle.
A successful verdict establishes that the bundle is internally
consistent, cryptographically intact since sealing, and bound to a
qualified electronic timestamp from an EU-accredited Trust Service
Provider.

It does **not**, on its own, establish that the screenshot or HTML
faithfully represent what an ordinary visitor would have seen at the
captured URL — that question depends on the trustworthiness of the
capture process and is supported (but not proved) by the bundled video
recording, HAR network log, and TLS evidence. A complete forensic
opinion combines this cryptographic verification with the visual and
network record, and any contextual evidence available to the examiner.

See the **Threat model** section below for a precise statement of what
each layer catches and what is out of scope.

## Install

```bash
pip install gpa-verify
```

Requires Python 3.9+. Two pure-Python wheels are installed
automatically: `asn1crypto` (RFC3161 / CMS / X.509 parsing) and
`cryptography` (RSA / ECDSA signature verification).

> **Note on Python command name:** On Linux and macOS the command is
> `python3` and `pip3`; on Windows it is `python` and `pip`.

## Use

```bash
gpa-verify path/to/GetProofAnchor_Evidence_*.zip
```

```
GetProofAnchor Evidence Verifier
────────────────────────────────────────────────────────────────
  Proof ID:       aeb2b103-d7c5-441c-b540-c0df600a34cf
  Bundle format:  getproofanchor-evidence-2
  Generated at:   2026-05-07T08:30:25Z

  [PASS]  bundle_integrity
          31/31 files OK

  [PASS]  cross_references
          5/5 cross-checks OK

  [PASS]  chain_integrity
          1 entries, all linked

  [PASS]  eidas_signature
          valid RFC3161 token, signed by CN=SK TIMESTAMPING UNIT 2026R,
          gen_time=2026-05-07T08:30:24+00:00

  [PASS]  anchor_canonical_hash
          canonical SHA matches manifest (968f0c691384c87c...)

  [PASS]  ots_receipt
          valid OTS proof for anchor SHA 968f0c69..., bitcoin status=pending

  [PASS]  tls_evidence
          leaf cert SHA-256 matches tls.json (e7668f38708d0411...)

────────────────────────────────────────────────────────────────
  ✓ VERIFIED  (7 passed, 0 failed, 0 skipped)
```

### JSON output for automation

```bash
gpa-verify --json bundle.zip > report.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | All checks passed |
| 1    | At least one check failed |
| 2    | Invalid arguments / cannot read input |
| 3    | Input is not verifiable by itself (unsealed plain copy or unsealed `report.pdf` without `--original`) |

## Forensic Browser outputs

`gpa-verify` also verifies the outputs of the GetProofAnchor **Forensic
Browser** desktop app. The input kind is detected automatically:

```bash
gpa-verify GetProofAnchor_sess-1792572420814.zip            # ZIP package
gpa-verify GetProofAnchor_sess-1792572400480.pdf            # PAdES-sealed PDF
gpa-verify GetProofAnchor_sess-1792572400480.pdf --tsl EE.xml   # + qualified status
gpa-verify GetProofAnchor_sess-1792572400480_bez-pecete.pdf \
           --original GetProofAnchor_sess-1792572400480.pdf # unsealed copy vs. original
```

| Input | What a `VERIFIED` verdict proves |
|-------|----------------------------------|
| **ZIP package** (`getproofanchor-lite-2`) | Every file matches `manifest.json`; every *sealed* file (screenshots, HTML, HAR, DNS, capture metadata, `proof.json`, optional MHTML/video — one `pages/NN/` directory per captured page) matches the hash listed in `timestamp/eidas_payload.json`, whose SHA-256 is the message imprint of the RFC 3161 token `timestamp/eidas.tsr`. The token signature, signed attributes, TSA certificate chain and the TSA's *granted* status at genTime in the bundled EU Trusted List are checked. Unsealed files (report, token, certificates, TSL snapshot) are reported as such. |
| **Sealed PDF** (PAdES document time-stamp, `/ETSI.RFC3161`) | The `/ByteRange` covers the whole file except the `/Contents` value; the embedded time-stamp's imprint equals the hash of those bytes, so the report **and every embedded artefact** (`/EmbeddedFiles`) existed in this exact form at genTime. Each attachment is listed with its SHA-256 and compared to the embedded `manifest.json` and `proof.json`. Any revision appended after the time-stamp is classified: Document Security Store / VRI / further document time-stamps are permitted (LTV); anything else is reported as **modified after sealing**, with the byte length and SHA-256 of the sealed version. |
| **Plain copy** (`*_bez-pecete.pdf`, unsealed) | Alone: nothing — it is reported as `NOT VERIFIABLE BY ITSELF` (exit 3) together with the identification it carries (sealed file name, SHA-256, session id, time-stamp serial and time, read from its QR code and printed text). With `--original`: the original is fully verified, and the copy's identification data must match it exactly. It is **not** proven that the copy's pages are a faithful rendering of the original. |

Sealed PDFs embed no Trusted List, so the TSA's qualified status is
reported as *not checked* unless you pass `--tsl` (a Trusted List `.xml` or a
directory of them; a Forensic Browser/SaaS ZIP is also accepted and its
`timestamp/tsl/*.xml` is used). `summary.qualified` and the verdict line say
which applies: `per_supplied_tsl`, `not_checked` or `failed`. The XML
signature of a Trusted List is **not** verified, so a list taken from an
evidence file is only as trustworthy as that file. For an independent check,
download the official list of the TSA's member state (Estonia:
<https://sr.riik.ee/tsl/estonian-tsl.xml>) and pass it with `--tsl`.
`--certs PEM` adds TSA CA certificates for chain building.

### Pinned trust roots (`tsa_trust_root`)

A Trusted List or root certificate shipped *inside* an evidence file comes
from the same party as the timestamp, so on its own it proves nothing. Every
input therefore also runs `tsa_trust_root`. The TSA signer certificate must:

* chain to a root key **pinned inside gpa-verify** (`src/gpa_verify/trust.py`),
  every link's signature verified, every issuer a CA certificate
  (basicConstraints cA, keyUsage keyCertSign, pathLenConstraint) and every
  certificate valid at genTime;
* be issued **directly by an SK time-stamping CA** (*SK TSA CA 2023R*) or by
  the root itself (SK's older TSA certificates were issued by EE
  Certification Centre Root CA). The same roots also anchor SK's ID-card,
  Smart-ID and e-seal CAs; a certificate issued under those cannot pass as a
  TSA;
* carry exactly the critical `id-kp-timeStamping` extended key usage and not
  be a CA.

Pinned roots:

| Root | SHA-256 (DER) |
|------|---------------|
| SK ID Solutions ROOT G1R | `d012da1a62193928c5b4d89d2a72495b1f77ea5d54f23956bc1df2f75528fefb` |
| SK ID Solutions ROOT G1E | `a272de102a8038f7e100eacfb6db1c930d3cb9f51d76b218de3a4a433bcfd182` |
| EE Certification Centre Root CA | `3e84ba4342908516e77573c0992f0979ca084e4685681ff195ccba8a229b8a76` |

These are the roots of SK ID Solutions AS, the qualified trust service
provider whose TSA GetProofAnchor and the Forensic Browser use; compare them
with <https://c.sk.ee/>. *SK TSA CA 2023R*
(SHA-256 `cce90c83b505f4bb21ce618ca77e607b8593018b5aa3ee34d7007eb1f2bf11ac`) is
bundled as the pinned time-stamping CA; it also completes the chain offline for
sealed PDFs. A timestamp from any other TSA fails this check unless you trust
its root explicitly with `--trust-root root.pem` (repeatable); under a root you
supply, any CA chain to it is accepted.

### Limits on hostile input

PDFs: at most 64 MB per decoded stream and 256 MB per document, predictor
parameters must fit the data, at most 64 signature dictionaries. ZIPs: at most
1 GiB per member, 4 GiB in total, compression ratio 1000:1 for members above
16 MiB, no duplicate member names. Inputs beyond these limits FAIL.

The formats are documented in
[docs/forensic-browser-formats.md](docs/forensic-browser-formats.md).
The PDF parser and the QR-code reader are small pure-Python modules —
no extra dependencies.

## What it actually checks

Verification runs in seven layers, each tightening the forensic claim.
**All layers must pass for a `VERIFIED` verdict.**

### Layer 1 — Bundle integrity

Every file declared in `manifest.json` exists and its SHA-256 matches.
Catches any byte-level tampering with the bundle.

### Layer 2 — Cross-references

`proof.json`'s SHA-256 claims for `screenshot.png`, `page.html`,
`content.txt`, and `capture/capture_meta.json` agree with actual file
contents. Sidecar `*.sha256` files agree. Catches selective tamper that
fixes one file but forgets another.

### Layer 3 — Chain integrity

`chain/proof_chain.jsonl` entries form a valid hash chain:
`entry_hash == SHA256(prev_hash | event_type | proof_id | data_hash)`,
recursively verified. `chain/chain_head.json` matches the last entry.
Catches tampering with the append-only event log.

### Layer 4 — eIDAS signature

**This is the cryptographic heart of the verification.**
The RFC3161 token in `timestamp/eidas.tsr` is verified for:

1. **Status** — token grant status is `granted` or `granted_with_mods`.
2. **Imprint** — the message digest the TSA signed equals
   `SHA256(timestamp/eidas_payload.json)`. Binds the timestamp to *this*
   evidence bundle, not someone else's.
3. **CMS signature** — the `SignedData` blob is verified against the
   signer certificate's public key, with proper signed-attributes
   re-encoding (`[0]` → `SET OF` per RFC 5652).
4. **timeStamping EKU** — the signer certificate has the
   `id-kp-timeStamping` Extended Key Usage. Defends against substitution
   from a non-timestamping certificate.

Together these prove the token can ONLY have been issued by the named
TSA, and ONLY for our exact payload.

Supported signature algorithms: RSA-PKCS1v15, ECDSA, RSA-PSS (across
SHA-256, SHA-384, SHA-512 digests).

### TSA trust root (`tsa_trust_root`, 1.6.0)

The signer certificate must be issued by the pinned SK time-stamping CA and
chain through CA certificates to a root pinned in gpa-verify (see *Pinned
trust roots* above). `tsl_qualified` (the bundled EU Trusted List)
remains an additional check of the TSA's qualified status at genTime.

### Layer 5 — Anchor canonical hash

`manifest.anchor.payload_sha256` equals SHA-256 of the canonical JSON
of `anchor/anchor_payload.json` (sorted keys, no whitespace, UTF-8).
Catches anchor receipts pointing to a different chain than ours.

### Layer 6 — OTS receipt structure

`anchor/anchor_receipt.ots` is a valid OpenTimestamps proof and its
file-hash field equals the anchor canonical SHA. Catches substituted
Bitcoin anchors. (Full Bitcoin block confirmation requires a Bitcoin
node and is therefore out of scope; use the [`ots`
client](https://opentimestamps.org/) for that.)

### Layer 7 — TLS evidence

`tls/leaf_cert.pem` SHA-256 fingerprint matches the `network/tls.json`
claim. Confirms the TLS leaf certificate stored in the bundle is the
same one observed at capture time.

### Anchor witness (informational)

`chain/anchor_witness.jsonl` links this proof's chain entry to the chain
head covered by the OpenTimestamps anchor; since 1.6.0 the last witness
`seq` must equal the anchored `seq`. The witness carries only
`(seq, prev_hash, entry_hash)` and those hashes cannot be recomputed from
the bundle, so this check is **informational** — it is not proof that the
Bitcoin anchor covers the evidence, and it never fails a bundle on its own
account beyond detecting an inconsistent witness.

### Anchor inclusion (anchor v3, since 1.6.0)

Bundles generated since 2026-10-21 carry `anchor/inclusion.json` once the
proof has been included in an anchor — normally within minutes of the
qualified timestamp; older downloads do not gain it (re-download). The check
recomputes

    leaf = SHA256("gpa-anchor-leaf-v3" 0x00 proof_id 0x00 SHA256(timestamp/eidas_payload.json))

walks the RFC 6962 audit path (leaf node `SHA256(0x00‖leaf)`, inner node
`SHA256(0x01‖left‖right)`, verified per RFC 9162 §2.1.3.2 with
`leaf_index` / `leaf_count`) to `merkle_root`, and confirms that the v3
anchor payload commits to that root, that SHA-256 of the canonical anchor
payload equals `anchor_payload_sha256` and the shipped payload file, and
that the `.ots` receipt header names that digest and carries an attestation.

**`verified` (PASS) means exactly:** content ↔ eIDAS payload whose qualified
timestamp verified in `eidas_signature` (signature, messageDigest, imprint) ↔
Merkle root ↔ OTS receipt digest. Bitcoin block confirmation of the content
anchor's receipt is a **separate** result (`extra.bitcoin_verification`, only
with `--bitcoin-rpc`; or run `ots verify -f <anchor payload file> <receipt>`).
That GetProofAnchor issued the anchor is shown only by the online verifier's
anchor registry.

Results: `verified` (PASS), `unverifiable` (SKIP — unparsable or
attestation-less receipt, or the payload's qualified timestamp did not
verify; see `extra.reasons`), `not_present` (SKIP), `failed` (FAIL).

## Threat model

`gpa-verify` defends against the following attacks:

| Attack | Caught by |
|--------|-----------|
| Modify any file (image, HTML, HAR, etc.) | Layer 1 |
| Modify file + manifest SHA | Layer 2 (proof.json) |
| Modify chain entry | Layer 3 |
| Forge eIDAS payload + update all SHAs | Layer 4 (imprint mismatch) |
| Substitute eIDAS token from non-TSA cert | Layer 4 (EKU check) |
| Self-made TSA + edited Trusted List inside the bundle | `tsa_trust_root` (pinned SK roots) |
| Substitute anchor for a different chain | Layer 5 |
| Substitute OTS receipt | Layer 6 |
| Substitute leaf TLS cert | Layer 7 |
| Fabricated chain witness (hashes only) | Anchor witness (last seq must equal anchored seq; informational) |
| Graft another proof's inclusion proof / edit eIDAS payload under a v3 anchor | Anchor inclusion |

It does **not** verify:

* **Whether the OpenTimestamps receipt has been confirmed in a Bitcoin
  block.** This requires an online Bitcoin node — use the `ots`
  client.
* **Whether the TSA's certificate is currently listed on the EU
  Trusted List.** The bundle includes a snapshot of the EU Trusted
  List as supporting context, but real-time validation against the
  live list is out of scope for an offline tool.
* **Whether the captured page actually showed what the screenshot
  shows.** This is a content question, not a cryptographic one. The
  bundled `capture.webm` video, HAR network log, and TLS evidence
  exist to support that forensic judgement, but interpreting them is
  the job of a qualified examiner.

## API

```python
from gpa_verify import verify_bytes

kind, report = verify_bytes(open("any-output.pdf", "rb").read())
print(kind, report.summary["verdict"])   # e.g. "sealed_pdf VERIFIED"
```

```python
from gpa_verify import verify_evidence_zip

with open("evidence.zip", "rb") as f:
    report = verify_evidence_zip(f.read())

if report.all_passed:
    print(f"VERIFIED  proof {report.proof_id}")
else:
    for c in report.checks:
        if not c.passed and not c.skipped:
            print(f"FAIL  {c.name}: {c.detail}")
```

## Building from source

```bash
git clone https://github.com/Getproofanchor/gpa-verify.git
cd gpa-verify
pip install -e .[dev]
pytest
```

## License

MIT — see [LICENSE](LICENSE).

This tool is published as open source so any forensic expert,
court-appointed examiner, or independent journalist can audit the
verification logic line by line. The cryptographic algorithms used
(RFC 3161, CMS / RFC 5652, X.509, SHA-256, RSA, ECDSA, OpenTimestamps)
are open standards.

## Standards & references

* **eIDAS Regulation (EU) 910/2014**, Article 41 — qualified
  electronic timestamps and their legal effect across EU Member States
* **ETSI EN 319 422** — Time-stamping protocol and electronic
  time-stamp profiles
* **ETSI EN 319 421** — Policy and security requirements for trust
  service providers issuing time-stamps
* **ETSI EN 319 102-1** — Procedures for creation and validation of
  AdES digital signatures
* **ISO/IEC 27037:2012** — Guidelines for identification, collection,
  acquisition and preservation of digital evidence
* **RFC 3161** — Time-Stamp Protocol (TSP)
* **RFC 5652** — Cryptographic Message Syntax (CMS)
* **RFC 5280** — X.509 certificates
* [**OpenTimestamps**](https://opentimestamps.org/) — Bitcoin-anchored timestamps
* [**EU Trusted List**](https://ec.europa.eu/tools/lotl/eu-lotl.xml) — qualified TSPs
