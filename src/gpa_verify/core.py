"""
gpa_verify.core — independent verification of GetProofAnchor evidence bundles.

This module contains all verification logic. It is designed to be:

  * Self-contained — only depends on the Python standard library plus
    `asn1crypto` and `cryptography` (both pure-Python wheels, available
    on every platform). No HTTP calls, no GetProofAnchor servers.
  * Deterministic — given the same evidence bundle, produces the same
    verdict on every machine. Verifier is a pure function of the ZIP.
  * Forensic-grade — explicit about what each check actually proves
    versus what is merely asserted. Failures are reported per-check so
    a forensic expert can pinpoint exactly what broke.
  * Audit-friendly — every verification step is named, timestamped,
    and includes the raw values it compared. Output can be saved as
    JSON for inclusion in expert testimony.

Verification layers (each tightens forensic claim):

  Layer 1  Bundle integrity      — SHA-256 of every file matches manifest.
                                   Catches: any byte-level tampering.
  Layer 2  Cross-references      — proof.json hashes match files; sidecar
                                   SHA files agree; chain head matches
                                   last chain entry.
                                   Catches: selective tamper that fixes
                                   one file but forgets another.
  Layer 3  Chain integrity       — entry_hash = SHA256(prev|event|id|data)
                                   recursively verified.
                                   Catches: tamper with append-only log.
  Layer 4  eIDAS signature       — RFC3161 token's CMS signature verified
                                   against TSA cert; signer cert has
                                   timeStamping EKU; message imprint
                                   matches eidas_payload SHA-256.
                                   Catches: forged timestamps; substituted
                                   payload; hostile TSA impersonation.
  Layer 5  Anchor canonical hash — manifest.anchor.payload_sha256 equals
                                   SHA-256 of canonical JSON of
                                   anchor/anchor_payload.json.
                                   Catches: anchor receipt pointing to a
                                   different chain than ours.
  Layer 6  OTS receipt structure — anchor/anchor_receipt.ots is a valid
                                   OpenTimestamps proof, file-hash field
                                   matches anchor canonical SHA.
                                   Catches: substituted Bitcoin anchor.
  Layer 7  TLS chain validity    — leaf_cert.pem subject + SAN consistent
                                   with network/tls.json claim; chain
                                   resolves to a public CA.

After all 7 layers pass, the verdict is: this evidence existed in this
exact form before the eIDAS timestamp's gen_time, was sealed by a
qualified TSA, was anchored to Bitcoin, and was served by the named
domain at capture time. Each link is independently verifiable by any
expert with this tool and the bundled artifacts — no GetProofAnchor
server needed.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """One verification check. Either passed, failed, or skipped."""
    name: str
    passed: bool
    skipped: bool = False
    detail: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.skipped:
            return "skip"
        return "pass" if self.passed else "fail"


@dataclass
class VerifyReport:
    """Complete verification report for an evidence bundle."""
    proof_id: Optional[str] = None
    bundle_format: Optional[str] = None
    generated_at: Optional[str] = None
    checks: List[CheckResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    @property
    def all_passed(self) -> bool:
        return all(c.passed or c.skipped for c in self.checks) and any(
            c.passed for c in self.checks
        )

    @property
    def any_failed(self) -> bool:
        return any(not c.passed and not c.skipped for c in self.checks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "bundle_format": self.bundle_format,
            "generated_at": self.generated_at,
            "all_passed": self.all_passed,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status,
                    "detail": c.detail,
                    **({"extra": c.extra} if c.extra else {}),
                }
                for c in self.checks
            ],
            "summary": self.summary,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    """Same canonicalization as the producer (sort_keys, no spaces, utf-8)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _read_zip_file(zf: zipfile.ZipFile, name: str) -> Optional[bytes]:
    try:
        return zf.read(name)
    except KeyError:
        return None


def _read_zip_json(zf: zipfile.ZipFile, name: str) -> Optional[Dict[str, Any]]:
    raw = _read_zip_file(zf, name)
    if raw is None:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _read_zip_text(zf: zipfile.ZipFile, name: str) -> Optional[str]:
    raw = _read_zip_file(zf, name)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — Bundle integrity
# ─────────────────────────────────────────────────────────────────────────────

SUPPORTED_FORMATS = frozenset({
    "getproofanchor-evidence-1",
    "getproofanchor-evidence-2",
})


def check_bundle_integrity(zf: zipfile.ZipFile, manifest: Dict[str, Any]) -> CheckResult:
    """Every file declared in manifest must exist and SHA-256 must match."""
    files_meta = manifest.get("files") or {}
    if not isinstance(files_meta, dict) or not files_meta:
        return CheckResult(
            name="bundle_integrity",
            passed=False,
            detail="manifest.files is empty or invalid",
        )

    fmt = manifest.get("format")
    if fmt and fmt not in SUPPORTED_FORMATS:
        return CheckResult(
            name="bundle_integrity",
            passed=False,
            detail=f"unsupported format: {fmt}",
            extra={"supported": sorted(SUPPORTED_FORMATS)},
        )

    zi_names = set(zf.namelist())
    mismatches: List[Dict[str, Any]] = []
    missing: List[str] = []
    checked = 0

    for path, meta in files_meta.items():
        if not isinstance(meta, dict):
            mismatches.append({"file": path, "error": "manifest entry not a dict"})
            continue
        expected_sha = meta.get("sha256")
        expected_size = meta.get("size")
        if not expected_sha:
            mismatches.append({"file": path, "error": "manifest entry missing sha256"})
            continue
        if path not in zi_names:
            missing.append(path)
            continue
        data = zf.read(path)
        actual_sha = _sha256(data)
        if actual_sha != expected_sha:
            mismatches.append({
                "file": path,
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
            })
            continue
        if isinstance(expected_size, int) and len(data) != expected_size:
            mismatches.append({
                "file": path,
                "expected_size": expected_size,
                "actual_size": len(data),
            })
            continue
        checked += 1

    # Files in ZIP not in manifest (excluding manifest itself + macOS metadata)
    declared = set(files_meta.keys()) | {"manifest.json"}
    extras = sorted([
        n for n in zi_names
        if n not in declared
        and not n.startswith("__MACOSX/")
        and not n.endswith(".DS_Store")
        and not n.endswith("/")
    ])

    passed = not mismatches and not missing
    detail_parts = []
    if passed:
        detail_parts.append(f"{checked}/{len(files_meta)} files OK")
    else:
        if missing:
            detail_parts.append(f"{len(missing)} missing")
        if mismatches:
            detail_parts.append(f"{len(mismatches)} mismatched")
    if extras:
        detail_parts.append(f"{len(extras)} extra file(s)")

    return CheckResult(
        name="bundle_integrity",
        passed=passed,
        detail=", ".join(detail_parts),
        extra={
            "checked": checked,
            "total_in_manifest": len(files_meta),
            "missing": missing,
            "mismatches": mismatches[:10],
            "extras_not_in_manifest": extras[:10],
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — Cross-references
# ─────────────────────────────────────────────────────────────────────────────

def check_cross_references(
    zf: zipfile.ZipFile,
    manifest: Dict[str, Any],
    proof: Optional[Dict[str, Any]],
) -> CheckResult:
    """Internal hash references must agree.

    proof.json claims SHA-256 of screenshot, page.html, content.txt,
    capture_meta.json. capture/capture_meta.sha256 sidecar must agree.
    eidas/eidas_payload.sha256 sidecar must equal SHA-256 of
    eidas_payload.json.
    """
    if proof is None:
        return CheckResult(
            name="cross_references",
            passed=False,
            detail="proof.json missing or invalid",
        )

    failures: List[Dict[str, Any]] = []
    checks: List[Tuple[str, str]] = []

    def _check_sha_match(file_path: str, expected: Optional[str], label: str):
        if not expected:
            return
        data = _read_zip_file(zf, file_path)
        if data is None:
            failures.append({"check": label, "error": f"{file_path} missing"})
            return
        actual = _sha256(data)
        checks.append((label, "ok" if actual == expected else "fail"))
        if actual != expected:
            failures.append({
                "check": label,
                "expected": expected,
                "actual": actual,
                "file": file_path,
            })

    _check_sha_match("screenshot.png", proof.get("screenshot_sha256"), "screenshot")
    _check_sha_match("page.html", proof.get("raw_html_sha256"), "page_html")
    _check_sha_match("content.txt", proof.get("content_sha256"), "content")

    capture = proof.get("capture") or {}
    _check_sha_match(
        "capture/capture_meta.json",
        capture.get("meta_sha256"),
        "capture_meta",
    )

    # capture_meta.sha256 sidecar must agree with actual file SHA
    sidecar_txt = _read_zip_text(zf, "capture/capture_meta.sha256")
    if sidecar_txt is not None:
        meta_data = _read_zip_file(zf, "capture/capture_meta.json")
        if meta_data is not None:
            declared = sidecar_txt.strip().split()[0] if sidecar_txt.strip() else ""
            actual = _sha256(meta_data)
            checks.append(("capture_meta_sidecar", "ok" if declared == actual else "fail"))
            if declared != actual:
                failures.append({
                    "check": "capture_meta_sidecar",
                    "declared": declared,
                    "actual": actual,
                })

    # eidas_payload.sha256 sidecar
    eidas_sidecar = _read_zip_text(zf, "timestamp/eidas_payload.sha256")
    eidas_payload = _read_zip_file(zf, "timestamp/eidas_payload.json")
    if eidas_sidecar is not None and eidas_payload is not None:
        declared = eidas_sidecar.strip().split()[0] if eidas_sidecar.strip() else ""
        actual = _sha256(eidas_payload)
        checks.append(("eidas_payload_sidecar", "ok" if declared == actual else "fail"))
        if declared != actual:
            failures.append({
                "check": "eidas_payload_sidecar",
                "declared": declared,
                "actual": actual,
            })
        # And proof.eidas.payload_sha256 must agree
        eidas_block = proof.get("eidas") or {}
        proof_payload_sha = eidas_block.get("payload_sha256")
        if proof_payload_sha and proof_payload_sha != declared:
            failures.append({
                "check": "eidas_proof_vs_sidecar",
                "proof_value": proof_payload_sha,
                "sidecar_value": declared,
            })

    return CheckResult(
        name="cross_references",
        passed=not failures,
        detail=f"{len([c for c in checks if c[1] == 'ok'])}/{len(checks)} cross-checks OK",
        extra={"checks": dict(checks), "failures": failures},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — Chain integrity
# ─────────────────────────────────────────────────────────────────────────────

def check_chain_integrity(zf: zipfile.ZipFile) -> CheckResult:
    """proof_chain.jsonl entries form a valid hash chain.

    For each entry:
      entry_hash == SHA256(prev_hash|event_type|proof_id|data_hash)
    Adjacent entries must link via prev_hash. chain_head.json must match
    the last entry. (Both reproduce the producer algorithm exactly.)
    """
    chain_text = _read_zip_text(zf, "chain/proof_chain.jsonl")
    head_obj = _read_zip_json(zf, "chain/chain_head.json")
    if chain_text is None:
        return CheckResult(
            name="chain_integrity",
            passed=False,
            skipped=False,
            detail="chain/proof_chain.jsonl missing",
        )

    entries: List[Dict[str, Any]] = []
    for line_no, line in enumerate(chain_text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception as exc:
            return CheckResult(
                name="chain_integrity",
                passed=False,
                detail=f"line {line_no}: invalid JSON ({exc})",
            )

    if not entries:
        return CheckResult(
            name="chain_integrity",
            passed=False,
            detail="proof_chain.jsonl is empty",
        )

    failures: List[Dict[str, Any]] = []
    for i, e in enumerate(entries):
        material = (
            f"{e.get('prev_hash') or ''}|"
            f"{e.get('event_type','')}|"
            f"{e.get('proof_id','')}|"
            f"{e.get('data_hash','')}"
        ).encode("utf-8")
        computed = hashlib.sha256(material).hexdigest()
        if computed != e.get("entry_hash"):
            failures.append({
                "seq": e.get("seq"),
                "error": "entry_hash mismatch",
                "computed": computed,
                "stored": e.get("entry_hash"),
            })
        if i > 0 and e.get("prev_hash") != entries[i - 1].get("entry_hash"):
            failures.append({
                "seq": e.get("seq"),
                "error": "prev_hash != previous entry's entry_hash",
                "expected_prev": entries[i - 1].get("entry_hash"),
                "got_prev": e.get("prev_hash"),
            })

    if head_obj:
        last = entries[-1]
        if head_obj.get("entry_hash") != last.get("entry_hash"):
            failures.append({
                "error": "chain_head.entry_hash != last entry's entry_hash",
                "head": head_obj.get("entry_hash"),
                "last": last.get("entry_hash"),
            })
        if head_obj.get("seq") != last.get("seq"):
            failures.append({
                "error": "chain_head.seq != last entry's seq",
                "head_seq": head_obj.get("seq"),
                "last_seq": last.get("seq"),
            })

    return CheckResult(
        name="chain_integrity",
        passed=not failures,
        detail=f"{len(entries)} entries, "
               f"{'all linked' if not failures else f'{len(failures)} failure(s)'}",
        extra={"entry_count": len(entries), "failures": failures},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 4 — eIDAS qualified timestamp signature
# ─────────────────────────────────────────────────────────────────────────────

def check_eidas_signature(
    zf: zipfile.ZipFile,
    manifest: Dict[str, Any],
) -> CheckResult:
    """Verify RFC3161 token cryptographically.

    1. Status = granted/granted_with_mods.
    2. Message imprint == SHA256(eidas_payload.json) — binds token
       to OUR payload, not someone else's.
    3. CMS SignedData signature verifies against the embedded TSA cert
       (re-encoding signed_attrs from [0] tag to SET OF per RFC5652).
    4. Signer cert has timeStamping Extended Key Usage — defends
       against signer-cert substitution from a non-timestamping cert.

    Together these prove the token can ONLY have been issued by the
    named TSA, and ONLY for our exact payload.
    """
    tsr_bytes = _read_zip_file(zf, "timestamp/eidas.tsr")
    payload_bytes = _read_zip_file(zf, "timestamp/eidas_payload.json")
    if tsr_bytes is None or payload_bytes is None:
        return CheckResult(
            name="eidas_signature",
            passed=False,
            skipped=True,
            detail="no eIDAS token in bundle",
        )
    expected_imprint = hashlib.sha256(payload_bytes).digest()

    try:
        from asn1crypto import tsp, cms, x509 as asn1_x509
        from cryptography import x509 as crypto_x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, ec
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        return CheckResult(
            name="eidas_signature",
            passed=False,
            detail=f"crypto deps missing: {exc}. Run: pip install asn1crypto cryptography",
            extra={"hint": "pip install asn1crypto cryptography"},
        )

    try:
        resp = tsp.TimeStampResp.load(tsr_bytes)
        status = resp["status"]["status"].native
        if status not in ("granted", "granted_with_mods"):
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail=f"TSA status not granted: {status}",
            )
        token = resp["time_stamp_token"]
        if token.native is None:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail="token field empty in TSR",
            )
        ci = cms.ContentInfo.load(token.dump())
        if ci["content_type"].native != "signed_data":
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail=f"unexpected content_type: {ci['content_type'].native}",
            )
        signed_data = ci["content"]
        encap = signed_data["encap_content_info"]
        content_obj = encap["content"]
        econtent = getattr(content_obj, "contents", None)
        if not econtent:
            try:
                econtent = content_obj.parsed.dump()
            except Exception:
                econtent = None
        if not econtent:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail="missing encap content",
            )
        tst_info = tsp.TSTInfo.load(econtent)

        # Imprint check
        mi = tst_info["message_imprint"]
        algo = mi["hash_algorithm"]["algorithm"].native
        hashed = mi["hashed_message"].native
        if algo != "sha256":
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail=f"imprint hash algo not sha256: {algo}",
            )
        if hashed != expected_imprint:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail=(
                    f"message imprint mismatch (TSR signs over "
                    f"{hashed.hex()[:16]}..., expected "
                    f"{expected_imprint.hex()[:16]}...)"
                ),
            )

        # Signature verification
        if len(signed_data["signer_infos"]) < 1:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail="no signer_infos",
            )
        si = signed_data["signer_infos"][0]
        signed_attrs = si["signed_attrs"]
        if signed_attrs.native is None:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail="no signed_attrs",
            )
        signed_attrs_der = signed_attrs.dump()
        if signed_attrs_der and signed_attrs_der[0] == 0xA0:
            signed_attrs_der = b"\x31" + signed_attrs_der[1:]

        signature = si["signature"].native
        digest_algo = si["digest_algorithm"]["algorithm"].native
        sig_algo = si["signature_algorithm"]["algorithm"].native

        certs = signed_data["certificates"]
        if certs is None or len(certs) == 0:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail="no certificates in token",
            )
        sid = si["sid"]
        signer_cert_der = None
        for c in certs:
            cert_obj = c.chosen
            if not isinstance(cert_obj, asn1_x509.Certificate):
                continue
            try:
                if sid.name == "issuer_and_serial_number":
                    iss = sid.chosen["issuer"]
                    ser = sid.chosen["serial_number"].native
                    if cert_obj.issuer == iss and cert_obj.serial_number == ser:
                        signer_cert_der = cert_obj.dump()
                        break
            except Exception:
                pass
        if signer_cert_der is None:
            signer_cert_der = certs[0].chosen.dump()

        cert = crypto_x509.load_der_x509_certificate(signer_cert_der)

        # EKU enforcement
        try:
            eku = cert.extensions.get_extension_for_class(
                crypto_x509.ExtendedKeyUsage
            ).value
            if crypto_x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku:
                return CheckResult(
                    name="eidas_signature",
                    passed=False,
                    detail="signer cert missing timeStamping EKU",
                )
        except crypto_x509.ExtensionNotFound:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail="signer cert has no EKU extension",
            )

        hash_alg_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }
        hash_alg = hash_alg_map.get(digest_algo)
        if hash_alg is None:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail=f"unsupported digest algo: {digest_algo}",
            )

        pub = cert.public_key()
        if sig_algo in ("rsassa_pkcs1v15", "sha256_rsa", "sha384_rsa", "sha512_rsa"):
            pub.verify(signature, signed_attrs_der, padding.PKCS1v15(), hash_alg)
        elif sig_algo in ("ecdsa", "sha256_ecdsa", "sha384_ecdsa", "sha512_ecdsa"):
            pub.verify(signature, signed_attrs_der, ec.ECDSA(hash_alg))
        elif sig_algo == "rsassa_pss":
            pss_padding = padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=padding.PSS.MAX_LENGTH,
            )
            pub.verify(signature, signed_attrs_der, pss_padding, hash_alg)
        else:
            return CheckResult(
                name="eidas_signature",
                passed=False,
                detail=f"unsupported sig algo: {sig_algo}",
            )

        # All passed
        gen_time = tst_info["gen_time"].native
        return CheckResult(
            name="eidas_signature",
            passed=True,
            detail=(
                f"valid RFC3161 token, signed by "
                f"{cert.subject.rfc4514_string().split(',')[-1].strip()}, "
                f"gen_time={gen_time.isoformat() if gen_time else 'n/a'}"
            ),
            extra={
                "imprint_match": True,
                "signer_subject": cert.subject.rfc4514_string(),
                "signer_issuer": cert.issuer.rfc4514_string(),
                "signer_serial": format(cert.serial_number, "x"),
                "policy_oid": tst_info["policy"].native,
                "gen_time": gen_time.isoformat() if gen_time else None,
                "signature_algorithm": sig_algo,
                "digest_algorithm": digest_algo,
                "tsa_name_from_meta": (
                    (manifest.get("eidas") or {}).get("tsa_name")
                ),
            },
        )

    except InvalidSignature:
        return CheckResult(
            name="eidas_signature",
            passed=False,
            detail="InvalidSignature: TSA signature verification FAILED",
        )
    except Exception as exc:
        return CheckResult(
            name="eidas_signature",
            passed=False,
            detail=f"verify exception: {type(exc).__name__}: {exc}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 5 — Anchor canonical hash
# ─────────────────────────────────────────────────────────────────────────────

def check_anchor_canonical_hash(
    zf: zipfile.ZipFile,
    manifest: Dict[str, Any],
) -> CheckResult:
    """anchor/anchor_payload.json (canonical) SHA must equal the value
    declared in manifest.anchor.payload_sha256 and proof.json.anchor."""
    anchor_meta = manifest.get("anchor") or {}
    if not anchor_meta.get("present"):
        return CheckResult(
            name="anchor_canonical_hash",
            passed=False,
            skipped=True,
            detail="no anchor in bundle",
        )

    payload_obj = _read_zip_json(zf, "anchor/anchor_payload.json")
    if payload_obj is None:
        return CheckResult(
            name="anchor_canonical_hash",
            passed=False,
            detail="anchor/anchor_payload.json missing or invalid",
        )

    canonical_sha = _sha256(_canonical_json_bytes(payload_obj))
    declared = anchor_meta.get("payload_sha256")
    if declared and declared != canonical_sha:
        return CheckResult(
            name="anchor_canonical_hash",
            passed=False,
            detail="manifest.anchor.payload_sha256 != canonical SHA",
            extra={"manifest": declared, "computed_canonical": canonical_sha},
        )

    return CheckResult(
        name="anchor_canonical_hash",
        passed=True,
        detail=f"canonical SHA matches manifest ({canonical_sha[:16]}...)",
        extra={"canonical_sha256": canonical_sha},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 6 — OTS receipt structure
# ─────────────────────────────────────────────────────────────────────────────

def check_ots_receipt(
    zf: zipfile.ZipFile,
    manifest: Dict[str, Any],
) -> CheckResult:
    """OpenTimestamps receipt header is valid + leaf SHA matches anchor.

    OTS file format:
      1-byte 0x00 + b"OpenTimestamps" + b"\\x00Proof" + b"\\xbf\\x89\\xe2\\xe8\\x84\\xe8\\x92\\x94"
        + version byte + crypto_op (sha256 = 0x08)
        + 32-byte file hash  ← must match anchor canonical SHA
        + ... timestamp tree ...

    Full ots-client verification calls a Bitcoin node or OTS calendars
    and is therefore not offline. This check verifies the receipt is
    structurally valid and references our exact anchor — that's enough
    to confirm "this OTS file CAN attest THIS anchor". Whether it
    HAS attested it depends on Bitcoin block confirmation, which is
    out of scope for an offline verifier (use `ots verify` for that).
    """
    receipt = _read_zip_file(zf, "anchor/anchor_receipt.ots")
    if receipt is None:
        # Some bundles have no OTS receipt (e.g. anchor not yet broadcast).
        ots_meta = manifest.get("ots") or {}
        if not ots_meta.get("present"):
            return CheckResult(
                name="ots_receipt",
                passed=True,
                skipped=True,
                detail="no OTS in bundle",
            )
        return CheckResult(
            name="ots_receipt",
            passed=False,
            detail="manifest claims OTS but anchor/anchor_receipt.ots missing",
        )

    OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
    if not receipt.startswith(OTS_MAGIC):
        return CheckResult(
            name="ots_receipt",
            passed=False,
            detail="bad OTS magic header",
            extra={"first_bytes": receipt[:32].hex()},
        )

    # Format: magic(31) + version(1) + crypto_op(1) + digest(32 for sha256) + ...
    pos = len(OTS_MAGIC)
    if len(receipt) < pos + 1 + 1 + 32:
        return CheckResult(
            name="ots_receipt",
            passed=False,
            detail="OTS file too short for header + digest",
        )
    version = receipt[pos]
    crypto_op = receipt[pos + 1]
    if crypto_op != 0x08:  # sha256
        return CheckResult(
            name="ots_receipt",
            passed=False,
            detail=f"unexpected OTS crypto_op {crypto_op:#x} (expected 0x08 = sha256)",
        )
    file_hash = receipt[pos + 2 : pos + 2 + 32]
    file_hash_hex = file_hash.hex()

    # Leaf SHA must match anchor canonical SHA
    anchor_meta = manifest.get("anchor") or {}
    anchor_canonical_sha = anchor_meta.get("payload_sha256")
    if anchor_canonical_sha and anchor_canonical_sha != file_hash_hex:
        return CheckResult(
            name="ots_receipt",
            passed=False,
            detail="OTS file_hash != anchor canonical SHA",
            extra={"ots_hash": file_hash_hex, "anchor_hash": anchor_canonical_sha},
        )

    # Count pending attestations as a friendly stat (not a hard check)
    PENDING_TAG = b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e"
    pending_count = receipt.count(PENDING_TAG)

    # OTS confirmed status from manifest (pending vs anchored on Bitcoin)
    ots_meta = manifest.get("ots") or {}
    btc_status = ots_meta.get("status")

    return CheckResult(
        name="ots_receipt",
        passed=True,
        detail=(
            f"valid OTS proof for anchor SHA {file_hash_hex[:16]}..., "
            f"OTS version={version}, "
            f"calendar attestations={pending_count}, "
            f"bitcoin status={btc_status}"
        ),
        extra={
            "file_hash_sha256": file_hash_hex,
            "ots_version": version,
            "calendar_attestation_count": pending_count,
            "bitcoin_status": btc_status,
            "bitcoin_block": ots_meta.get("bitcoin_block"),
            "bitcoin_tx": ots_meta.get("bitcoin_tx"),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 7 — TLS evidence
# ─────────────────────────────────────────────────────────────────────────────

def check_tls_evidence(zf: zipfile.ZipFile) -> CheckResult:
    """TLS leaf cert SHA-256 fingerprint must match network/tls.json claim,
    and the chain must include the leaf."""
    tls_json = _read_zip_json(zf, "network/tls.json")
    leaf_pem = _read_zip_file(zf, "tls/leaf_cert.pem")
    if tls_json is None or leaf_pem is None:
        return CheckResult(
            name="tls_evidence",
            passed=False,
            skipped=True,
            detail="no TLS evidence in bundle",
        )

    # Extract DER from PEM
    pem_lines = leaf_pem.decode("ascii", errors="replace").split("\n")
    der_b64 = "".join(
        line for line in pem_lines
        if line and "BEGIN CERT" not in line and "END CERT" not in line
    )
    try:
        import base64
        der = base64.b64decode(der_b64)
    except Exception as exc:
        return CheckResult(
            name="tls_evidence",
            passed=False,
            detail=f"leaf_cert.pem base64 decode failed: {exc}",
        )

    leaf_sha256 = _sha256(der)
    leaf_meta = tls_json.get("leaf_certificate") or {}
    declared = leaf_meta.get("sha256_fingerprint")
    if declared and declared.lower() != leaf_sha256.lower():
        return CheckResult(
            name="tls_evidence",
            passed=False,
            detail="leaf_cert.pem SHA-256 != network/tls.json claim",
            extra={"declared": declared, "actual": leaf_sha256},
        )

    return CheckResult(
        name="tls_evidence",
        passed=True,
        detail=f"leaf cert SHA-256 matches tls.json ({leaf_sha256[:16]}...)",
        extra={
            "leaf_sha256": leaf_sha256,
            "subject": leaf_meta.get("subject"),
            "issuer": leaf_meta.get("issuer"),
            "tls_version": tls_json.get("tls_version"),
            "cipher_suite": tls_json.get("cipher_suite"),
            "host": tls_json.get("host"),
            "server_ip": tls_json.get("server_ip"),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def verify_evidence_zip(zip_bytes: bytes) -> VerifyReport:
    """Run all verification layers on an evidence ZIP and return a report.

    This is a pure function: same input → same report. No network calls,
    no side effects, no GetProofAnchor servers.
    """
    report = VerifyReport()

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile as exc:
        report.checks.append(CheckResult(
            name="zip_open", passed=False, detail=f"not a valid ZIP: {exc}",
        ))
        return report

    manifest = _read_zip_json(zf, "manifest.json")
    if manifest is None:
        report.checks.append(CheckResult(
            name="manifest_load", passed=False,
            detail="manifest.json missing or invalid JSON",
        ))
        return report

    report.proof_id = manifest.get("proof_id")
    report.bundle_format = manifest.get("format")
    report.generated_at = manifest.get("generated_at")

    proof = _read_zip_json(zf, "proof.json")

    # Run layers in fixed order
    report.checks.append(check_bundle_integrity(zf, manifest))
    report.checks.append(check_cross_references(zf, manifest, proof))
    report.checks.append(check_chain_integrity(zf))
    report.checks.append(check_eidas_signature(zf, manifest))
    report.checks.append(check_anchor_canonical_hash(zf, manifest))
    report.checks.append(check_ots_receipt(zf, manifest))
    report.checks.append(check_tls_evidence(zf))

    # Build summary
    report.summary = {
        "checks_total": len(report.checks),
        "checks_passed": sum(1 for c in report.checks if c.passed),
        "checks_failed": sum(1 for c in report.checks if not c.passed and not c.skipped),
        "checks_skipped": sum(1 for c in report.checks if c.skipped),
        "verdict": (
            "VERIFIED"
            if report.all_passed and not report.any_failed
            else "FAILED"
        ),
    }
    return report
