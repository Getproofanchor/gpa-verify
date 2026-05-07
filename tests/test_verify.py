"""
Tests for gpa-verify.

The fixture ZIPs in tests/fixtures/ are real evidence bundles from
the GetProofAnchor production system. Tests verify that:

  * Pristine bundles produce VERIFIED verdict.
  * Tampered bundles produce FAILED verdict, and the failed check
    exactly identifies what was tampered with.

Add new fixtures by dropping a real evidence ZIP into tests/fixtures/.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from gpa_verify import verify_evidence_zip


FIXTURES = Path(__file__).parent / "fixtures"


def _list_fixtures() -> list[Path]:
    return sorted(FIXTURES.glob("*.zip")) if FIXTURES.exists() else []


pytestmark = pytest.mark.skipif(
    not _list_fixtures(),
    reason="no evidence fixtures (drop a real .zip into tests/fixtures/ to enable)",
)


@pytest.fixture(params=_list_fixtures(), ids=lambda p: p.name)
def fixture_zip(request) -> bytes:
    return request.param.read_bytes()


# ─── Positive tests ─────────────────────────────────────────────────────────

def test_pristine_bundle_verifies(fixture_zip: bytes):
    """A pristine bundle should pass every check."""
    report = verify_evidence_zip(fixture_zip)
    assert not report.any_failed, (
        f"unexpected failure(s):\n"
        + "\n".join(
            f"  {c.name}: {c.detail}"
            for c in report.checks
            if not c.passed and not c.skipped
        )
    )
    assert report.summary["verdict"] == "VERIFIED"


def test_check_count(fixture_zip: bytes):
    """All 7 verification layers must run."""
    report = verify_evidence_zip(fixture_zip)
    assert report.summary["checks_total"] == 7
    expected_layers = {
        "bundle_integrity",
        "cross_references",
        "chain_integrity",
        "eidas_signature",
        "anchor_canonical_hash",
        "ots_receipt",
        "tls_evidence",
    }
    actual = {c.name for c in report.checks}
    assert actual == expected_layers


def test_proof_id_extracted(fixture_zip: bytes):
    """Proof ID must be present in report."""
    report = verify_evidence_zip(fixture_zip)
    assert report.proof_id is not None
    # UUID format
    assert len(report.proof_id) == 36
    assert report.proof_id.count("-") == 4


# ─── Negative tests ─────────────────────────────────────────────────────────

def _modify_zip_file(orig: bytes, target: str, modify_fn) -> bytes:
    """Rebuild ZIP with one file modified. Manifest stays unchanged so
    integrity check should fail."""
    src = zipfile.ZipFile(io.BytesIO(orig), "r")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == target:
                data = modify_fn(data)
            dst.writestr(name, data)
    return out.getvalue()


def test_tamper_screenshot_one_byte_detected(fixture_zip: bytes):
    """Flipping a single byte in screenshot.png must be detected."""
    tampered = _modify_zip_file(
        fixture_zip,
        "screenshot.png",
        lambda d: d[:-1] + bytes([d[-1] ^ 1]) if d else d,
    )
    report = verify_evidence_zip(tampered)
    assert report.any_failed
    integrity = next(c for c in report.checks if c.name == "bundle_integrity")
    assert not integrity.passed
    # The mismatch must list screenshot.png explicitly
    mismatches = integrity.extra.get("mismatches", [])
    assert any(m.get("file") == "screenshot.png" for m in mismatches)


def test_tamper_eidas_tsr_detected(fixture_zip: bytes):
    """Replacing eidas.tsr must be detected (integrity OR signature)."""
    tampered = _modify_zip_file(
        fixture_zip,
        "timestamp/eidas.tsr",
        lambda d: b"\x00" * len(d),
    )
    report = verify_evidence_zip(tampered)
    assert report.any_failed


def test_forge_eidas_payload_detected(fixture_zip: bytes):
    """The trickiest attack: forge eidas_payload.json AND update every
    SHA reference (manifest, sidecar, proof.json). Pure integrity check
    passes — only cryptographic signature verification catches it."""
    src = zipfile.ZipFile(io.BytesIO(fixture_zip), "r")
    payload_obj = json.loads(src.read("timestamp/eidas_payload.json"))
    manifest = json.loads(src.read("manifest.json"))
    proof = json.loads(src.read("proof.json"))

    # Modify payload (forge a different screenshot SHA in the eIDAS payload)
    payload_obj["screenshot_sha256"] = "0" * 64
    new_payload = json.dumps(
        payload_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()
    new_sha = hashlib.sha256(new_payload).hexdigest()
    new_sidecar = (new_sha + "\n").encode()
    new_sidecar_sha = hashlib.sha256(new_sidecar).hexdigest()

    # Update everywhere SHA appears so pure integrity passes
    manifest["files"]["timestamp/eidas_payload.json"]["sha256"] = new_sha
    manifest["files"]["timestamp/eidas_payload.json"]["size"] = len(new_payload)
    manifest["files"]["timestamp/eidas_payload.sha256"]["sha256"] = new_sidecar_sha
    manifest["files"]["timestamp/eidas_payload.sha256"]["size"] = len(new_sidecar)
    if (manifest.get("eidas") or {}).get("payload_sha256"):
        manifest["eidas"]["payload_sha256"] = new_sha
    if (proof.get("eidas") or {}).get("payload_sha256"):
        proof["eidas"]["payload_sha256"] = new_sha

    new_proof = json.dumps(proof, ensure_ascii=False, indent=2).encode()
    manifest["files"]["proof.json"]["sha256"] = hashlib.sha256(new_proof).hexdigest()
    manifest["files"]["proof.json"]["size"] = len(new_proof)
    new_manifest = json.dumps(manifest, ensure_ascii=False, indent=2).encode()

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for name in src.namelist():
            if name == "timestamp/eidas_payload.json":
                dst.writestr(name, new_payload)
            elif name == "timestamp/eidas_payload.sha256":
                dst.writestr(name, new_sidecar)
            elif name == "manifest.json":
                dst.writestr(name, new_manifest)
            elif name == "proof.json":
                dst.writestr(name, new_proof)
            else:
                dst.writestr(name, src.read(name))

    report = verify_evidence_zip(out.getvalue())
    # Integrity may pass (we updated all SHA refs); signature MUST fail
    sig = next(c for c in report.checks if c.name == "eidas_signature")
    assert not sig.passed, (
        "forged payload not detected by signature check — this is the "
        "attack scenario the cryptographic verification exists to defeat"
    )
    assert "imprint" in (sig.detail or "").lower()


def test_invalid_zip_rejected():
    """Non-ZIP input should be rejected gracefully (no exception)."""
    report = verify_evidence_zip(b"not a zip file")
    assert report.any_failed
    assert any(c.name == "zip_open" for c in report.checks)


def test_empty_zip_rejected():
    """Empty ZIP should be rejected."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        pass
    report = verify_evidence_zip(out.getvalue())
    assert report.any_failed


def test_zip_without_manifest_rejected():
    """ZIP missing manifest.json should be rejected."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("hello.txt", "world")
    report = verify_evidence_zip(out.getvalue())
    assert report.any_failed
    assert any(c.name == "manifest_load" for c in report.checks)
