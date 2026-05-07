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
| 2    | Invalid arguments / cannot read ZIP |

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

## Threat model

`gpa-verify` defends against the following attacks:

| Attack | Caught by |
|--------|-----------|
| Modify any file (image, HTML, HAR, etc.) | Layer 1 |
| Modify file + manifest SHA | Layer 2 (proof.json) |
| Modify chain entry | Layer 3 |
| Forge eIDAS payload + update all SHAs | Layer 4 (imprint mismatch) |
| Substitute eIDAS token from non-TSA cert | Layer 4 (EKU check) |
| Substitute anchor for a different chain | Layer 5 |
| Substitute OTS receipt | Layer 6 |
| Substitute leaf TLS cert | Layer 7 |

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
