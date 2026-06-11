# gpa-verify v1.4.0 — EU Trusted List validation + real Bitcoin verification

This release adds the two checks that close the gaps a forensic reviewer would
flag in v1.3.0: **eIDAS qualified-status validation against the EU Trusted
List**, and **real Bitcoin block verification** against your own node.

## New: Layer 8 `tsl_qualified` (offline)

v1.3.0 proved the RFC3161 token was cryptographically signed by the cert
embedded in it and that the cert had the timeStamping EKU — but not that the
cert is a *qualified* TSU recognised by an EU member state. (A self-issued
cert can carry a timeStamping EKU too.)

`tsl_qualified` closes that gap, fully offline: it parses the EU Trusted List
bundled in the evidence ZIP (`timestamp/tsl/<CC>.xml`, ETSI TS 119 612) and
confirms the signer certificate is listed under a service that is **both**
type `TSA/QTST` (Qualified Time Stamp) **and** status `granted`. On bundles
that predate per-country TSL bundling it skips cleanly instead of failing.

## New: `--bitcoin-rpc` real Bitcoin verification (opt-in, online)

By default the OTS layer stays fully offline and reports Bitcoin status from
the manifest only (a producer assertion, not a proof). Pass `--bitcoin-rpc`
with the JSON-RPC URL of a Bitcoin Core node **you operate** and the tool
performs genuine verification:

1. reads the receipt's `BitcoinBlockHeaderAttestation` (does **not** upgrade
   or modify the receipt);
2. fetches the attested block's header via `getblockhash` + `getblockheader`
   on your node;
3. confirms the OTS-committed merkle root equals the block header's merkleroot
   using the canonical `opentimestamps` library.

No calendars, no block explorers — the only network call is to your own node.
If the receipt has no Bitcoin attestation yet (still pending across
calendars), online mode reports that honestly instead of claiming confirmed.

```bash
pip install gpa-verify[bitcoin]
gpa-verify --bitcoin-rpc "http://user:pass@127.0.0.1:8332" evidence.zip
```

## Changes

- Verification layers: 7 → 8 (`tsl_qualified` after `eidas_signature`).
- `verify_evidence_zip(zip_bytes, *, bitcoin_rpc=None)` — new keyword-only
  argument; the default call remains a pure offline function.
- New optional dependency extra `bitcoin` (pulls `opentimestamps`). The core
  offline verifier still needs only `asn1crypto` + `cryptography`.

## Tests

- `test_check_count` updated to 8 layers.
- `test_tsl_qualified_when_present` and `test_tamper_tsl_cert_swap_detected`
  added; Bitcoin merkle logic proven against the real `opentimestamps` library
  with a mocked node (correct root verifies, wrong root rejected).

## Honest limitations

- `tsl_qualified` validates against the TSL bundled in the evidence and
  reflects status as of that snapshot; it does not yet validate the TSL's own
  XML signature against the EU List-of-Lists (LOTL) trust anchor — a heavier
  separate step on the roadmap.
- Offline mode still cannot confirm Bitcoin block inclusion by design; use
  `--bitcoin-rpc` for that.

**Full verification on both reference bundles (server + browser captures):
8/8 layers, VERIFIED.**
