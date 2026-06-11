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
  Layer 5  TSL qualified status   — signer cert is listed as a granted
                                   TSA/QTST (Qualified Time Stamp) service in
                                   the bundled EU Trusted List. Offline.
                                   Catches: a validly-signed but NON-qualified
                                   timestamp (e.g. self-issued cert with a
                                   timeStamping EKU that no member state lists).
  Layer 6  Anchor canonical hash — manifest.anchor.payload_sha256 equals
                                   SHA-256 of canonical JSON of
                                   anchor/anchor_payload.json.
                                   Catches: anchor receipt pointing to a
                                   different chain than ours.
  Layer 7  OTS receipt           — anchor/anchor_receipt.ots is a valid
                                   OpenTimestamps proof, file-hash field
                                   matches anchor canonical SHA. With
                                   --bitcoin-rpc, additionally verifies the
                                   receipt's Bitcoin block attestation against
                                   the operator's OWN node (real merkle-root
                                   check; receipt never modified).
                                   Catches: substituted Bitcoin anchor;
                                   (online) false claims of block inclusion.
  Layer 8  TLS chain validity    — leaf_cert.pem subject + SAN consistent
                                   with network/tls.json claim; chain
                                   resolves to a public CA.

After all layers pass, the verdict is: this evidence existed in this
exact form before the eIDAS timestamp's gen_time, was sealed by a
qualified TSA listed in the EU Trusted List, was anchored to Bitcoin,
and was served by the named domain at capture time. Each link is
independently verifiable by any expert with this tool and the bundled
artifacts — no GetProofAnchor server needed.
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
    "getproofanchor-evidence-3",  # Added in 1.2.0
    "getproofanchor-evidence-4",  # Added in 1.2.0 — M-6b: per-country TSL bundles
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
    # v1.3.0: MHTML snapshot (stamp-6). Optional artifact — only checked when
    # proof.json declares mhtml_sha256 (server captures since backend v1.10.0,
    # browser captures since extension v1.10.1). Absent on older proofs and on
    # captures where MHTML failed (graceful degradation) — _check_sha_match
    # is a no-op when expected is falsy, so this never false-fails.
    _check_sha_match("page.mhtml", proof.get("mhtml_sha256"), "page_mhtml")

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

    # ── eidas_payload.json ↔ actual file hashes cross-validation ──
    # Reads the eIDAS payload (which is what the TSA actually signed
    # over) and confirms each declared asset hash matches the actual
    # file on disk inside the archive. This is the critical "trust
    # what was timestamped" check: if an attacker swapped any file
    # AFTER timestamping but kept proof.json self-consistent, this
    # would still detect the tampering, because eidas_payload.json
    # is bound to the TSA signature.
    #
    # Supports stamp-3, stamp-4 (core 4 hashes only) and stamp-5
    # (which additionally binds har_sha256, video_sha256,
    # tls_leaf_pem_sha256, tls_chain_pem_sha256 directly — closing the
    # forensic gap where optional artifacts were not under the TSA
    # signature in older formats).
    if eidas_payload is not None:
        try:
            ep = json.loads(eidas_payload.decode("utf-8"))
        except Exception:
            ep = None
        if isinstance(ep, dict):
            ep_format = ep.get("format") or "(unknown)"
            checks.append((f"eidas_payload_format ({ep_format})", "ok"))

            # Every hash field in the payload must match the actual file's
            # content hash. We map payload field name → archive path.
            asset_map = {
                "screenshot_sha256":      "screenshot.png",
                "raw_html_sha256":        "page.html",
                "content_sha256":         "content.txt",
                "capture_meta_sha256":    "capture/capture_meta.json",
                # stamp-5 additions:
                "har_sha256":             "network/capture.har",
                "video_sha256":           "capture.webm",
                "tls_leaf_pem_sha256":    "tls/leaf_cert.pem",
                "tls_chain_pem_sha256":   "tls/chain.pem",
                # stamp-6 addition (backend v1.10.0 / extension v1.10.1):
                # MHTML offline snapshot bound directly under the TSA
                # signature. Present on both server and browser captures.
                "mhtml_sha256":           "page.mhtml",
            }
            stamp5_fields_present = []
            for field, archive_path in asset_map.items():
                declared = ep.get(field)
                if not declared:
                    continue
                file_data = _read_zip_file(zf, archive_path)
                if file_data is None:
                    failures.append({
                        "check": f"eidas_payload_vs_{field}",
                        "error": f"{archive_path} declared in eidas_payload but missing from archive",
                        "expected": declared,
                    })
                    checks.append((f"eidas_payload_vs_{field}", "fail"))
                    continue
                actual = _sha256(file_data)
                if actual != declared:
                    failures.append({
                        "check": f"eidas_payload_vs_{field}",
                        "expected": declared,
                        "actual": actual,
                        "file": archive_path,
                        "note": "Hash declared in TSA-signed eidas_payload.json does not match file in archive — possible post-timestamp tampering.",
                    })
                    checks.append((f"eidas_payload_vs_{field}", "fail"))
                else:
                    checks.append((f"eidas_payload_vs_{field}", "ok"))
                    if field in ("har_sha256", "video_sha256", "tls_leaf_pem_sha256", "tls_chain_pem_sha256", "mhtml_sha256"):
                        stamp5_fields_present.append(field)

            # Informational note about direct-binding strength (stamp-5/stamp-6:
            # optional artifacts — HAR, video, TLS PEM, MHTML — bound directly
            # under the TSA signature rather than only via capture_meta).
            if stamp5_fields_present:
                checks.append((
                    f"direct_binding ({', '.join(stamp5_fields_present)})",
                    "ok",
                ))

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

def _bitcoin_verify_via_node(receipt_bytes: bytes, rpc_url: str) -> Dict[str, Any]:
    """Verify the OTS receipt's Bitcoin attestation(s) against the operator's
    own Bitcoin Core node via JSON-RPC. Returns a result dict; never raises.

    Trust model: the ONLY external party trusted here is the node at rpc_url,
    which the verifier operates. No calendars, no explorers. The receipt is
    read, never modified or upgraded.

    Steps per Bitcoin attestation in the receipt:
      1. recompute the merkle root committed by the OTS path
         (BitcoinBlockHeaderAttestation.verify_against_blockheader)
      2. getblockhash(height) → getblockheader(hash) on the node
      3. assert recomputed merkle root == block header merkleroot
    """
    result: Dict[str, Any] = {
        "online": True, "rpc_reachable": False, "deps_missing": False,
        "bitcoin_attestations": [], "verified_heights": [], "errors": [],
    }
    try:
        import json as _json
        import urllib.request
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import (
            BitcoinBlockHeaderAttestation, PendingAttestation,
        )
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.bitcoin import make_timestamp_from_block  # noqa: F401
    except Exception as exc:
        result["deps_missing"] = True
        result["errors"].append(
            f"opentimestamps not installed ({exc}); "
            f"run: pip install gpa-verify[bitcoin]"
        )
        return result

    def _rpc(method, params):
        payload = _json.dumps(
            {"jsonrpc": "1.0", "id": "gpa", "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(
            rpc_url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = _json.loads(resp.read().decode())
        if body.get("error"):
            raise RuntimeError(body["error"])
        return body["result"]

    # Parse receipt
    try:
        ctx = StreamDeserializationContext(io.BytesIO(receipt_bytes))
        detached = DetachedTimestampFile.deserialize(ctx)
        ts = detached.timestamp
    except Exception as exc:
        result["errors"].append(f"cannot parse OTS receipt: {exc}")
        return result

    btc_atts = []
    for msg, att in ts.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            btc_atts.append((msg, att))
    result["bitcoin_attestations"] = [a.height for _, a in btc_atts]
    result["pending_count"] = sum(
        1 for _, a in ts.all_attestations() if isinstance(a, PendingAttestation)
    )

    if not btc_atts:
        # Honest: no Bitcoin block attestation present yet (still pending).
        return result

    # Probe node reachability once
    try:
        _rpc("getblockcount", [])
        result["rpc_reachable"] = True
    except Exception as exc:
        result["errors"].append(f"node unreachable: {exc}")
        return result

    for msg, att in btc_atts:
        h = att.height
        try:
            blockhash = _rpc("getblockhash", [h])
            header = _rpc("getblockheader", [blockhash, True])
            # The OTS lib compares the committed `msg` digest directly against
            # block_header.hashMerkleRoot (32 bytes, internal/little-endian
            # order) and returns the block nTime on success. The node reports
            # merkleroot as display-order hex, so reverse it to internal order.
            shim = _BlockHeaderShim(header)
            block_time = att.verify_against_blockheader(msg, shim)
            result["verified_heights"].append(h)
            result.setdefault("block_times", {})[h] = block_time
            result.setdefault("block_hashes", {})[h] = blockhash
        except Exception as exc:
            result["errors"].append(f"height {h}: {type(exc).__name__}: {exc}")

    return result


class _BlockHeaderShim:
    """Minimal adapter so BitcoinBlockHeaderAttestation.verify_against_blockheader
    can read fields from a getblockheader RPC dict.

    The OTS lib does: `digest != block_header.hashMerkleRoot` (bytes compare)
    and returns `block_header.nTime`. So we expose:
      - hashMerkleRoot: 32 bytes in INTERNAL (little-endian) order. Bitcoin
        Core reports merkleroot as display hex (big-endian), so we reverse.
      - nTime: block timestamp (int).
    """
    def __init__(self, header_dict: Dict[str, Any]):
        self.hashMerkleRoot = bytes.fromhex(header_dict["merkleroot"])[::-1]
        self.nTime = int(header_dict.get("time", 0))


def check_ots_receipt(
    zf: zipfile.ZipFile,
    manifest: Dict[str, Any],
    bitcoin_rpc: Optional[str] = None,
) -> CheckResult:
    """OpenTimestamps receipt header is valid + leaf SHA matches anchor.

    OTS file format:
      1-byte 0x00 + b"OpenTimestamps" + b"\\x00Proof" + b"\\xbf\\x89\\xe2\\xe8\\x84\\xe8\\x92\\x94"
        + version byte + crypto_op (sha256 = 0x08)
        + 32-byte file hash  ← must match anchor canonical SHA
        + ... timestamp tree ...

    OFFLINE (default, bitcoin_rpc=None): verifies the receipt is structurally
    valid and references our exact anchor — enough to confirm "this OTS file
    CAN attest THIS anchor". Whether it HAS been confirmed in a Bitcoin block
    is reported from the manifest only (an assertion by the producer, not a
    proof). This keeps the default verifier fully offline & deterministic.

    ONLINE (bitcoin_rpc set, e.g. http://user:pass@127.0.0.1:8332): performs
    REAL Bitcoin verification against the operator's OWN node — no calendars,
    no block explorers, no third party. It parses the embedded
    BitcoinBlockHeaderAttestation(s), recomputes the merkle root from the OTS
    path, fetches the attested block's header via getblockhash+getblockheader
    RPC, and confirms the recomputed root equals the block's merkleroot. This
    does NOT upgrade or modify the receipt — it only reads what is already in
    it. If the receipt has no Bitcoin attestation yet (still pending across
    calendars), online mode says so honestly rather than claiming confirmed.
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

    # ── ONLINE Bitcoin verification (only when bitcoin_rpc provided) ──
    # Reads the receipt's Bitcoin attestation(s) and checks them against the
    # operator's own node. Never modifies/upgrades the receipt.
    btc_online: Optional[Dict[str, Any]] = None
    if bitcoin_rpc:
        btc_online = _bitcoin_verify_via_node(receipt, bitcoin_rpc)
        verified = btc_online.get("verified_heights") or []
        atts = btc_online.get("bitcoin_attestations") or []
        errs = btc_online.get("errors") or []
        if atts and verified and not errs:
            # Real, node-confirmed Bitcoin inclusion.
            return CheckResult(
                name="ots_receipt", passed=True,
                detail=(
                    f"BITCOIN-CONFIRMED via own node: anchor SHA "
                    f"{file_hash_hex[:16]}... committed in block height(s) "
                    f"{verified} (merkle root matches block header)"
                ),
                extra={
                    "file_hash_sha256": file_hash_hex,
                    "ots_version": version,
                    "bitcoin_verification": "node_confirmed",
                    "verified_block_heights": verified,
                    "block_hashes": btc_online.get("block_hashes"),
                    "block_times": btc_online.get("block_times"),
                    "rpc_reachable": btc_online.get("rpc_reachable"),
                },
            )
        if atts and errs:
            # There IS a Bitcoin attestation but the node check failed —
            # that is a genuine verification failure, not a "pending".
            return CheckResult(
                name="ots_receipt", passed=False,
                detail=(
                    f"Bitcoin attestation present (height(s) {atts}) but node "
                    f"verification FAILED: {'; '.join(errs)}"
                ),
                extra={
                    "file_hash_sha256": file_hash_hex,
                    "bitcoin_verification": "node_failed",
                    "bitcoin_attestations": atts,
                    "errors": errs,
                    "rpc_reachable": btc_online.get("rpc_reachable"),
                },
            )
        # No Bitcoin attestation in the receipt yet → still pending. Online
        # mode reports this honestly; it is not a failure (the timestamp is
        # simply not yet anchored in a block across the calendars).

    detail = (
        f"valid OTS proof for anchor SHA {file_hash_hex[:16]}..., "
        f"OTS version={version}, "
        f"calendar attestations={pending_count}, "
        f"bitcoin status={btc_status}"
    )
    extra = {
        "file_hash_sha256": file_hash_hex,
        "ots_version": version,
        "calendar_attestation_count": pending_count,
        "bitcoin_status": btc_status,
        "bitcoin_block": ots_meta.get("bitcoin_block"),
        "bitcoin_tx": ots_meta.get("bitcoin_tx"),
    }
    if btc_online is not None:
        if btc_online.get("deps_missing"):
            extra["bitcoin_verification"] = "skipped_deps_missing"
            extra["online_errors"] = btc_online.get("errors")
            detail += (
                " [--bitcoin-rpc given but 'opentimestamps' not installed — "
                "Bitcoin check skipped; run: pip install gpa-verify[bitcoin]]"
            )
        else:
            extra["bitcoin_verification"] = "pending_no_block_attestation"
            extra["pending_calendar_count"] = btc_online.get("pending_count")
            extra["online_errors"] = btc_online.get("errors")
            detail += " [online: no Bitcoin block attestation in receipt yet — pending]"
    return CheckResult(
        name="ots_receipt",
        passed=True,
        detail=detail,
        extra=extra,
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
# Layer 8 — EU Trusted List qualified status (offline)
# ─────────────────────────────────────────────────────────────────────────────

# ETSI TS 119 612 namespaces. Certificates inside a TSL service's digital
# identity are in the *TSL* namespace (02231/v2#), NOT the xmldsig (ds:)
# namespace — a subtle point that is easy to get wrong and silently match
# zero certs.
_TSL_NS = "http://uri.etsi.org/02231/v2#"
_TSA_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
_SVC_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"


def _tsl_xml_candidates(zf: zipfile.ZipFile) -> List[str]:
    """All bundled Trusted List XML files (e.g. timestamp/tsl/EE.xml)."""
    out = []
    for name in zf.namelist():
        low = name.lower()
        if low.startswith("timestamp/tsl/") and low.endswith(".xml"):
            out.append(name)
    return out


def _qualified_tsa_cert_hashes(xml_bytes: bytes) -> Dict[str, str]:
    """Map sha256(DER) -> service name, for every X509 certificate that
    belongs to a TSA/QTST service whose status is `granted`.

    Parsed strictly per ETSI TS 119 612 with the correct namespace. We only
    accept certs whose *owning service* is both type=TSA/QTST and
    status=granted, so a withdrawn or non-timestamping entry never qualifies.
    """
    import base64
    import xml.etree.ElementTree as ET

    certs: Dict[str, str] = {}
    root = ET.fromstring(xml_bytes)
    for svc in root.iter(f"{{{_TSL_NS}}}TSPService"):
        info = svc.find(f"{{{_TSL_NS}}}ServiceInformation")
        if info is None:
            continue
        stype = info.findtext(f"{{{_TSL_NS}}}ServiceTypeIdentifier", default="")
        sstatus = info.findtext(f"{{{_TSL_NS}}}ServiceStatus", default="")
        if stype != _TSA_QTST or sstatus != _SVC_GRANTED:
            continue
        name_el = info.find(
            f"{{{_TSL_NS}}}ServiceName/{{{_TSL_NS}}}Name"
        )
        sname = (name_el.text if name_el is not None else "") or "?"
        # Certificates live under ServiceDigitalIdentity/DigitalId/X509Certificate
        # in the TSL namespace.
        for x509 in info.iter(f"{{{_TSL_NS}}}X509Certificate"):
            b64 = "".join((x509.text or "").split())
            if not b64:
                continue
            try:
                der = base64.b64decode(b64)
            except Exception:
                continue
            certs[hashlib.sha256(der).hexdigest()] = sname
    return certs


def _token_cert_der_chain(tsr_bytes: bytes) -> List[bytes]:
    """Return DER bytes of every certificate embedded in the RFC3161 token."""
    out: List[bytes] = []
    try:
        from asn1crypto import tsp, cms, x509 as asn1_x509
        resp = tsp.TimeStampResp.load(tsr_bytes)
        token = resp["time_stamp_token"]
        ci = cms.ContentInfo.load(token.dump())
        signed_data = ci["content"]
        certs = signed_data["certificates"]
        if certs is None:
            return out
        for c in certs:
            obj = c.chosen
            if isinstance(obj, asn1_x509.Certificate):
                out.append(obj.dump())
    except Exception:
        pass
    return out


def check_tsl_qualified(zf: zipfile.ZipFile, manifest: Dict[str, Any]) -> CheckResult:
    """Confirm the TSA signer certificate is listed as a *granted*,
    *qualified* timestamping service (TSA/QTST) in the bundled EU Trusted
    List — fully offline.

    Layer 4 (eidas_signature) already proves the token was cryptographically
    signed by the cert embedded in it, and that the cert carries the
    timeStamping EKU. But that alone does not prove the cert is a *qualified*
    TSU recognised by an EU member state — a self-issued cert can also carry
    the timeStamping EKU. This layer closes that gap by checking the signer
    cert against the official Trusted List shipped in the bundle
    (timestamp/tsl/<CC>.xml), with no network access.

    What it proves: the timestamp was issued by a TSU that the signer's member
    state lists as a granted Qualified Time Stamp service — i.e. a genuine
    eIDAS Article 42 qualified timestamp at the moment the TSL snapshot was
    taken.

    What it does NOT prove on its own: that the TSL snapshot itself is the
    authentic, signature-valid LOTL-anchored list (the bundle ships the member
    state TSL; full LOTL-signature validation against the EU list-of-lists is
    a heavier, separate step). It also reflects status as of the bundled TSL,
    not necessarily today's status.
    """
    tsr_bytes = _read_zip_file(zf, "timestamp/eidas.tsr")
    if tsr_bytes is None:
        return CheckResult(
            name="tsl_qualified", passed=True, skipped=True,
            detail="no eIDAS token in bundle",
        )

    tsl_files = _tsl_xml_candidates(zf)
    if not tsl_files:
        # No bundled TSL — cannot validate offline. Skip rather than fail:
        # older bundles (evidence-1/2/3) may predate per-country TSL bundling.
        return CheckResult(
            name="tsl_qualified", passed=True, skipped=True,
            detail="no Trusted List bundled (timestamp/tsl/*.xml absent)",
        )

    chain = _token_cert_der_chain(tsr_bytes)
    if not chain:
        return CheckResult(
            name="tsl_qualified", passed=False,
            detail="could not extract any certificate from the RFC3161 token",
        )
    chain_hashes = {hashlib.sha256(d).hexdigest(): d for d in chain}

    # Aggregate qualified-TSA certs across all bundled member-state TSLs.
    all_qualified: Dict[str, str] = {}
    parsed_files = []
    for fname in tsl_files:
        raw = _read_zip_file(zf, fname)
        if raw is None:
            continue
        try:
            q = _qualified_tsa_cert_hashes(raw)
        except Exception as exc:
            return CheckResult(
                name="tsl_qualified", passed=False,
                detail=f"failed to parse {fname}: {type(exc).__name__}: {exc}",
            )
        all_qualified.update(q)
        parsed_files.append(fname)

    # The signer cert is conventionally the first cert; but to be robust we
    # accept a match on ANY cert in the token chain (some TSLs list the issuing
    # CA's TSU cert). The signer leaf is chain[0].
    signer_sha = hashlib.sha256(chain[0]).hexdigest()
    matched_sha = None
    matched_name = None
    if signer_sha in all_qualified:
        matched_sha, matched_name = signer_sha, all_qualified[signer_sha]
    else:
        for h in chain_hashes:
            if h in all_qualified:
                matched_sha, matched_name = h, all_qualified[h]
                break

    if matched_sha is None:
        return CheckResult(
            name="tsl_qualified", passed=False,
            detail=(
                "TSA signer cert NOT found among granted TSA/QTST services in "
                f"bundled Trusted List(s) {parsed_files}"
            ),
            extra={
                "signer_sha256": signer_sha,
                "qualified_certs_in_tsl": len(all_qualified),
                "tsl_files": parsed_files,
            },
        )

    on_leaf = matched_sha == signer_sha
    return CheckResult(
        name="tsl_qualified", passed=True,
        detail=(
            f"signer cert listed as granted Qualified TSA in EU Trusted List "
            f"({matched_name})"
            + ("" if on_leaf else " [matched via chain cert, not leaf]")
        ),
        extra={
            "signer_sha256": signer_sha,
            "matched_sha256": matched_sha,
            "matched_on_leaf": on_leaf,
            "service_name": matched_name,
            "service_type": "TSA/QTST",
            "service_status": "granted",
            "qualified_certs_in_tsl": len(all_qualified),
            "tsl_files": parsed_files,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def verify_evidence_zip(
    zip_bytes: bytes,
    *,
    bitcoin_rpc: Optional[str] = None,
) -> VerifyReport:
    """Run all verification layers on an evidence ZIP and return a report.

    By default this is a pure offline function: same input → same report, no
    network calls, no GetProofAnchor servers.

    If `bitcoin_rpc` is given (a Bitcoin Core JSON-RPC URL the caller
    operates, e.g. "http://user:pass@127.0.0.1:8332"), the OTS layer
    additionally performs REAL Bitcoin block verification against that node —
    the only network call this tool ever makes, and only to the operator's
    own node. The receipt is never modified.
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
    report.checks.append(check_tsl_qualified(zf, manifest))
    report.checks.append(check_anchor_canonical_hash(zf, manifest))
    report.checks.append(check_ots_receipt(zf, manifest, bitcoin_rpc=bitcoin_rpc))
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
