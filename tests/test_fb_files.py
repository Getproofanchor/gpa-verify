"""
Forensic Browser "Files and documents" evidence (getproofanchor-files-1).

Fixtures in tests/fixtures/forensic_browser/files/ are real outputs of the
app's FilesEvidenceBuilder (see make_fixtures.py there): four files (PDF,
JPEG with EXIF, DOCX, text) from the three source types (local file, URL
with a redirect, browser download). They are time-stamped by the app's
self-made test TSA, so tsa_trust_root / tsl_qualified cannot pass; every
other check must. Tamper tests mutate the fixtures in memory.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from gpa_verify import verify_bytes
from gpa_verify.dispatch import detect_kind
from gpa_verify.forensic_browser import _check_files, verify_fb_zip, verify_plain_copy, verify_sealed_pdf

HERE = Path(__file__).parent / "fixtures"
FILES = HERE / "forensic_browser" / "files"
ZIP = FILES / "GetProofAnchor_files-zip.zip"
PDF = FILES / "GetProofAnchor_files-dual_pdf.pdf"
COPY = FILES / "GetProofAnchor_files-dual_pdf_bez-pecete.pdf"
WEB_SEALED = HERE / "forensic_browser" / "GetProofAnchor_sess-1792572400480.pdf"
WEB_ZIP = HERE / "forensic_browser" / "GetProofAnchor_sess-1792572420814.zip"
SAAS_FILE_DIGEST = [HERE / "fx_2165a04f-5e6c-4cf0-a5d3-00f232584b9a.zip",
                    HERE / "fx_32661144-2948-4a23-9c58-4c83dbf8b535.zip"]

pytestmark = pytest.mark.skipif(not (ZIP.exists() and PDF.exists() and COPY.exists()),
                                reason="files fixtures missing")

# Self-made test TSA: only trust anchoring can fail.
TRUST = {"tsa_trust_root", "tsl_qualified", "original.tsa_trust_root", "original.tsl_qualified",
         "copy_integrity"}


def _failed(rep):
    return {c.name for c in rep.checks if not c.passed and not c.skipped}


def _check(rep, name):
    return next(c for c in rep.checks if c.name == name)


def _rezip(src: bytes, replace=None, drop=(), add=None) -> bytes:
    replace = replace or {}
    zin = zipfile.ZipFile(io.BytesIO(src))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for n in zin.namelist():
            if n in drop:
                continue
            zo.writestr(n, replace.get(n, zin.read(n)))
        for n, d in (add or {}).items():
            zo.writestr(n, d)
    return out.getvalue()


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _members(b: bytes):
    z = zipfile.ZipFile(io.BytesIO(b))
    return {n: z.read(n) for n in z.namelist()}


def _with_manifest(m: dict, changes: dict) -> bytes:
    """Apply changes and rewrite manifest.json hashes (manifest is unsealed)."""
    m = dict(m)
    m.update(changes)
    man = json.loads(m["manifest.json"])
    for n, d in changes.items():
        if n == "manifest.json":
            continue
        if d is None:
            man["files"].pop(n, None)
            m.pop(n)
            continue
        man["files"][n] = {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d),
                           "sealed": man["files"].get(n, {}).get("sealed", False)}
    m["manifest.json"] = _canon(man)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for n, d in m.items():
            zo.writestr(n, d)
    return out.getvalue()


# ── dispatch: FB files vs SaaS file-digest ──────────────────────────────────
def test_detect_kinds():
    assert detect_kind(ZIP.read_bytes()) == "fb_zip"
    assert detect_kind(PDF.read_bytes()) == "sealed_pdf"
    assert detect_kind(COPY.read_bytes()) == "plain_copy"


@pytest.mark.parametrize("fx", SAAS_FILE_DIGEST, ids=lambda p: p.name[:11])
def test_saas_file_digest_not_routed_to_fb(fx):
    if not fx.exists():
        pytest.skip("SaaS fixture missing")
    data = fx.read_bytes()
    assert detect_kind(data) == "saas_zip"
    # even if proof.json pretends to come from the Forensic Browser
    m = _members(data)
    proof = json.loads(m["proof.json"])
    proof["app_version"] = "gpa-forensic-browser-1.5.0"
    forged = _rezip(data, replace={"proof.json": _canon(proof)})
    assert detect_kind(forged) == "saas_zip"
    kind, rep = verify_bytes(data)
    assert kind == "saas_zip" and _check(rep, "file_digest").passed


def test_fb_files_with_saas_markers_stays_fb_and_fails():
    data = ZIP.read_bytes()
    forged = _rezip(data, add={"files_manifest.json": b'{"format":"getproofanchor-file-digest-1","files":[]}'})
    kind, rep = verify_bytes(forged)
    assert kind == "fb_zip"
    assert "bundle_integrity" in _failed(rep)


def test_fb_files_relabelled_as_saas_fails():
    m = _members(ZIP.read_bytes())
    man = json.loads(m["manifest.json"])
    man["format"] = "getproofanchor-evidence-4"
    forged = _rezip(ZIP.read_bytes(), replace={"manifest.json": _canon(man)})
    kind, rep = verify_bytes(forged)
    assert kind == "saas_zip"
    assert rep.summary["verdict"] == "FAILED"


# ── ZIP ─────────────────────────────────────────────────────────────────────
def test_zip_pristine():
    rep = verify_fb_zip(ZIP.read_bytes())
    assert _failed(rep) <= TRUST, [(c.name, c.detail) for c in rep.checks if not c.passed]
    c = _check(rep, "files")
    assert c.passed and len(c.extra["files"]) == 4
    assert {f["source"] for f in c.extra["files"]} == {"local", "url", "download"}
    assert _check(rep, "fb_package").passed and _check(rep, "sealed_binding").passed
    assert _check(rep, "report_pdf").passed
    assert "files-1" in rep.bundle_format


def test_zip_tampered_file_detected():
    m = _members(ZIP.read_bytes())
    p = next(n for n in m if n.startswith("files/02/") and not n.endswith("source.json"))
    forged = _with_manifest(m, {p: m[p][:-1] + bytes([m[p][-1] ^ 1])})
    rep = verify_fb_zip(forged)
    assert {"sealed_binding", "files"} <= _failed(rep)


def test_zip_undeclared_file_detected():
    m = _members(ZIP.read_bytes())
    forged = _with_manifest(m, {"files/05/extra.txt": b"planted"})
    rep = verify_fb_zip(forged)
    assert "files" in _failed(rep)
    assert any("not declared" in f.get("error", "") for f in _check(rep, "files").extra["failures"])
    # planted inside an existing file directory as well
    forged = _with_manifest(m, {"files/01/second.pdf": b"%PDF-1.4"})
    assert "files" in _failed(verify_fb_zip(forged))


def test_zip_missing_source_json_detected():
    m = _members(ZIP.read_bytes())
    forged = _with_manifest(m, {"files/03/source.json": None})
    rep = verify_fb_zip(forged)
    assert {"files", "sealed_binding"} <= _failed(rep)


def test_zip_proof_rewritten_detected():
    """Changing proof.json (e.g. file_count) breaks the sealed binding."""
    m = _members(ZIP.read_bytes())
    proof = json.loads(m["proof.json"])
    proof["file_count"] = 3
    rep = verify_fb_zip(_with_manifest(m, {"proof.json": _canon(proof)}))
    assert {"sealed_binding", "files"} <= _failed(rep)


def _reader(m):
    return lambda n: m.get(n)


def test_check_files_unit_shapes():
    m = _members(ZIP.read_bytes())
    proof = json.loads(m["proof.json"])
    cm = json.loads(m["capture/capture_meta.json"])
    pfiles = json.loads(m["timestamp/eidas_payload.json"])["files"]
    names = list(m)
    ok = _check_files(proof, cm, _reader(m), names, pfiles, {})
    assert ok.passed, ok.extra
    bad = json.loads(json.dumps(proof))
    bad["files"][1]["index"] = 1                           # duplicate index
    assert not _check_files(bad, cm, _reader(m), names, pfiles, {}).passed
    bad = json.loads(json.dumps(proof))
    bad["files"][0]["name"] = "../../evil.pdf"              # unsafe name
    assert not _check_files(bad, cm, _reader(m), names, pfiles, {}).passed
    bad = json.loads(json.dumps(proof))
    bad["files"][0]["name"] = "source.json"
    assert not _check_files(bad, cm, _reader(m), names, pfiles, {}).passed
    bad = json.loads(json.dumps(proof))
    bad["files"][0]["sha512"] = "0" * 128                   # SHA-512 mismatch
    r = _check_files(bad, cm, _reader(m), names, pfiles, {})
    assert not r.passed and any("SHA-512" in f.get("error", "") for f in r.extra["failures"])
    bad = json.loads(json.dumps(proof))
    bad["file_count"] = 9
    assert not _check_files(bad, cm, _reader(m), names, pfiles, {}).passed
    bad = json.loads(json.dumps(proof))
    bad["files"][2]["source"]["type"] = "local"             # source.json says download
    assert not _check_files(bad, cm, _reader(m), names, pfiles, {}).passed


# ── PDF + plain copy ────────────────────────────────────────────────────────
def test_pdf_pristine():
    rep = verify_sealed_pdf(PDF.read_bytes())
    assert _failed(rep) <= TRUST, [(c.name, c.detail) for c in rep.checks if not c.passed]
    c = _check(rep, "evidence_consistency")
    assert c.passed and c.extra["kind"] == "files" and len(c.extra["files"]) == 4
    assert _check(rep, "attachments").passed
    assert "files-1" in rep.bundle_format


def test_pdf_byte_flip_detected():
    b = bytearray(PDF.read_bytes())
    b[len(b) // 3] ^= 0x01            # inside the time-stamped byte range
    rep = verify_sealed_pdf(bytes(b))
    assert _failed(rep) - TRUST


def test_plain_copy_alone_not_verifiable():
    kind, rep = verify_bytes(COPY.read_bytes())
    assert kind == "plain_copy" and rep.summary["verdict"] == "NOT_VERIFIABLE"
    assert _check(rep, "copy_identification").passed


def test_plain_copy_with_original():
    rep = verify_plain_copy(COPY.read_bytes(), original=PDF.read_bytes(), original_name=PDF.name)
    assert _failed(rep) <= TRUST, [(c.name, c.detail) for c in rep.checks if not c.passed]
    assert _check(rep, "copy_binding").passed
    cc = _check(rep, "copy_content_consistency")
    assert cc.passed and "URL" in cc.detail


def test_plain_copy_with_wrong_original_fails():
    if not WEB_SEALED.exists():
        pytest.skip("web fixture missing")
    rep = verify_plain_copy(COPY.read_bytes(), original=WEB_SEALED.read_bytes())
    assert "copy_binding" in _failed(rep)


def test_web_zip_unchanged_routing():
    if not WEB_ZIP.exists():
        pytest.skip("web fixture missing")
    kind, rep = verify_bytes(WEB_ZIP.read_bytes())
    assert kind == "fb_zip" and any(c.name == "pages" for c in rep.checks)
    assert not any(c.name == "files" for c in rep.checks)
