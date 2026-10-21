# gpa-verify 1.6.0 — Forensic Browser outputs, anchor v3 inclusion proofs, timestamp hardening

**This is a security release. Upgrade if you verify GetProofAnchor bundles.**

## What was wrong

**1. The Bitcoin anchor did not show that it covers the evidence.**
GetProofAnchor bundles carry an OpenTimestamps receipt for an anchor payload
that names the head of GetProofAnchor's internal hash chain. Version 1.5.0
linked a proof to that head with `chain/anchor_witness.jsonl`, a list of
`(seq, prev_hash, entry_hash)` triples. Those hashes cannot be recomputed from
the bundle, so any sequence of hashes that ends at the anchored head "links".
An independent audit showed that a one-line fabricated witness passed.

**2. Removing the qualified timestamp gave VERIFIED.** When
`timestamp/eidas.tsr` was deleted from a real eIDAS bundle (and the manifest
updated), every timestamp check turned into a SKIP and the verdict stayed
VERIFIED. Since `proof.json` and `manifest.json` are not sealed, content could
then be edited without the verdict changing.

**3. A token with a rewritten TSTInfo passed.** `eidas_signature` verified the
CMS signature over the signed attributes but did not compare the
`messageDigest` attribute with the TSTInfo actually present, so a token whose
message imprint had been replaced still verified.

## What changed

**`eidas_signature`** now:
- FAILS when the bundle declares a qualified timestamp but the token or the
  stamped payload is missing — the same rule as the GetProofAnchor online
  verifier;
- checks `messageDigest == H(TSTInfo)` with the SignerInfo digest algorithm.

Bundles of proofs that never had a qualified timestamp keep their 1.5.0 verdict.

**`anchor_witness` is informational.** The last witness `seq` must equal the
anchored `seq`; a witness that stops short is a skip, not a pass. Every result
says "informational (not independently recomputable)".

**New layer 11 `anchor_inclusion`.** Since 2026-10-21 the server builds, in
every anchor run, an RFC 6962 Merkle tree with one leaf per eIDAS-stamped
proof and commits its root in the anchor payload (`"v": 3`, `merkle_root`,
`leaf_count`, `leaf_algo`). Bundles carry the inclusion proof as
`anchor/inclusion.json` once the proof has been included in an anchor
(normally within minutes of stamping — re-download older packages).

**`verified` means exactly:**

    content digests ↔ timestamp/eidas_payload.json (its qualified timestamp verified:
    signature, messageDigest, imprint) ↔ leaf ↔ Merkle root ↔ v3 anchor payload
    ↔ digest in the .ots receipt header (with at least one attestation)

Two things it does **not** mean:
- *Existence at a Bitcoin block* is a separate result. Use `--bitcoin-rpc`
  (which now also checks the content anchor's receipt,
  `anchor/inclusion_anchor_receipt.ots`) or `ots verify -f <anchor payload
  file> <receipt>`.
- *That GetProofAnchor issued the anchor* is shown only by the online
  verifier's anchor registry.

Other results:
- `unverifiable` (SKIP): the receipt is unparsable or has no attestation, or
  the payload's qualified timestamp did not verify — see `extra.reasons`;
- `not_present` (SKIP): no `inclusion.json`;
- `failed` (FAIL): any inconsistency, including an invalid `proof_id` or
  non-lowercase hex.

## New: pinned TSA trust roots (`tsa_trust_root`)

Until now, offline, the TSA was judged only by the Trusted List bundled in the
evidence file — a list supplied by the same party as the timestamp. A forger
could ship a self-made TSA together with an edited list.

Every SaaS ZIP, Forensic Browser ZIP and sealed PDF now also runs
`tsa_trust_root`: the TSA signer certificate must chain (every signature
verified, every certificate valid at genTime) to one of the SK ID Solutions
roots pinned inside gpa-verify — ROOT G1R, ROOT G1E or EE Certification Centre
Root CA (SHA-256 fingerprints in the README; compare with https://c.sk.ee/).
Timestamps from another TSA fail unless its root is passed with
`--trust-root root.pem`. The public intermediate *SK TSA CA 2023R* is bundled
so that sealed PDFs (which embed only the TSU certificate) also complete the
chain offline; `tsa_chain` now passes for them without `--certs`.

Remaining limit: revocation (OCSP/CRL) is not checked, and the qualified
*status* at genTime still comes from the bundled Trusted List (`tsl_qualified`)
or `--tsl`. The online GetProofAnchor verifier uses its own EU Trusted List
cache.

## Impact on existing bundles

- Real bundles that verified with 1.5.0 still verify (all are stamped by SK ID
  Solutions and chain to ROOT G1R).
- SaaS ZIPs now run 12 checks (new `tsa_trust_root`).
- Bundles without `anchor/inclusion.json` report `anchor_inclusion` as SKIP.
- Bundles stripped of a declared qualified timestamp now FAIL; they should.
- New bundles stay readable by 1.5.0, which gives them the same verdict as
  before; only 1.6.0 can show the content binding.

## Upgrade

    pip install --upgrade gpa-verify

## New: Forensic Browser outputs

`gpa-verify <file>` now auto-detects and verifies the outputs of the
GetProofAnchor **Forensic Browser** desktop app:

- **ZIP packages** (`getproofanchor-lite-2`): every file against `manifest.json`,
  every sealed file against the time-stamped `eidas_payload.json`, per-page
  hashes, the RFC 3161 token, the TSA certificate chain and the qualified
  status from the EU Trusted List snapshot inside the package.
- **Sealed PDFs (PAdES document timestamp):** the signed byte range covers the
  whole file, the token matches it, embedded attachments match the embedded
  manifest. Bytes appended after sealing are accepted only if they are LTV data
  or another document timestamp; anything else is reported as
  **MODIFIED AFTER SEALING**. Sealed PDFs carry no Trusted List: pass
  `--tsl <file|dir|zip>` to check the qualified status offline.
- **Unsealed copies (`*_bez-pecete.pdf`):** reported as *not verifiable by
  itself* (exit code 3). With `--original <sealed.pdf>` the original is fully
  verified and the copy's identification data (QR code / printed text: session,
  SHA-256 and size of the sealed file, timestamp serial and time) must match it.

No new dependencies: PDF and QR parsing are implemented in pure Python. See
`docs/forensic-browser-formats.md`.

