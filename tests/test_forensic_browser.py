"""
Tests for Forensic Browser (desktop app) outputs: ZIP package, PAdES-sealed
PDF and unsealed plain copy.

Fixtures in tests/fixtures/forensic_browser/ are real captures made by the
project owner with the Forensic Browser (qualified time-stamps from SK ID
Solutions). Tamper tests mutate them in memory. A small synthetic TSA
(self-made root + TSU certificate) is used where a *valid* token over new
content is needed (multi-page package, strict token-profile checks).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from gpa_verify import verify_bytes, verify_evidence_zip
from gpa_verify import cli
from gpa_verify import pdfmini as P
from gpa_verify.dispatch import detect_kind
from gpa_verify.forensic_browser import (
    read_copy_identification,
    verify_fb_zip,
    verify_plain_copy,
    verify_sealed_pdf,
)
from gpa_verify.trust import extra_roots
from gpa_verify.tsp_verify import verify_token

FB = Path(__file__).parent / "fixtures" / "forensic_browser"
ZIP = FB / "GetProofAnchor_sess-1792572420814.zip"
SEALED = FB / "GetProofAnchor_sess-1792572400480.pdf"
COPY = FB / "GetProofAnchor_sess-1792572400480_bez-pecete.pdf"

pytestmark = pytest.mark.skipif(
    not (ZIP.exists() and SEALED.exists() and COPY.exists()),
    reason="Forensic Browser fixtures missing",
)


def _status(report, name):
    for c in report.checks:
        if c.name == name:
            return c.status
    raise KeyError(name)


def _failed(report):
    return {c.name for c in report.checks if not c.passed and not c.skipped}


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


def _flip(b: bytes, pos: int) -> bytes:
    ba = bytearray(b)
    ba[pos] ^= 0x01
    return bytes(ba)


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ═════════════════════════════════════════════════════════════════════════════
# Detection / dispatch
# ═════════════════════════════════════════════════════════════════════════════

def test_detect_kinds():
    assert detect_kind(ZIP.read_bytes()) == "fb_zip"
    assert detect_kind(SEALED.read_bytes()) == "sealed_pdf"
    assert detect_kind(COPY.read_bytes()) == "plain_copy"
    assert detect_kind(b"hello") == "unknown"


def test_core_entry_point_dispatches_fb_zip():
    """verify_evidence_zip (the 1.x API) must not reject FB packages."""
    r = verify_evidence_zip(ZIP.read_bytes())
    assert r.bundle_format.startswith("forensic-browser-zip")
    assert r.summary["verdict"] == "VERIFIED"


# ═════════════════════════════════════════════════════════════════════════════
# ZIP package
# ═════════════════════════════════════════════════════════════════════════════

def test_fb_zip_pristine_verifies():
    r = verify_fb_zip(ZIP.read_bytes())
    assert not r.any_failed, [(c.name, c.detail) for c in r.checks if c.status == "fail"]
    assert r.summary["verdict"] == "VERIFIED"
    assert r.proof_id == "sess-1792572420814"
    for name in ("bundle_integrity", "sealed_binding", "pages", "timestamp_token",
                 "tsa_chain", "tsl_qualified", "timestamp_metadata"):
        assert _status(r, name) == "pass", name
    assert r.summary["timestamp"]["serial"] == "7113423928149478945"


def test_fb_zip_edit_sealed_file_detected():
    src = ZIP.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(src))
    png = z.read("pages/01/screenshot.png")
    bad = _rezip(src, {"pages/01/screenshot.png": _flip(png, len(png) // 2)})
    r = verify_fb_zip(bad)
    assert {"bundle_integrity", "sealed_binding", "pages"} <= _failed(r)
    assert r.summary["verdict"] == "FAILED"


def test_fb_zip_edit_sealed_file_and_manifest_still_detected():
    """Recomputing manifest.json is not enough: the payload is time-stamped."""
    src = ZIP.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(src))
    html = z.read("pages/01/page.html").replace(b"<body", b"<body data-x=1", 1)
    man = json.loads(z.read("manifest.json"))
    man["files"]["pages/01/page.html"].update(sha256=hashlib.sha256(html).hexdigest(), size=len(html))
    bad = _rezip(src, {"pages/01/page.html": html, "manifest.json": json.dumps(man).encode()})
    r = verify_fb_zip(bad)
    assert _status(r, "bundle_integrity") == "pass"
    assert "sealed_binding" in _failed(r)


def test_fb_zip_forged_payload_detected():
    """Editing a file AND the payload (and sidecars, manifest) breaks the imprint."""
    src = ZIP.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(src))
    html = z.read("pages/01/page.html") + b"<!-- forged -->"
    payload = json.loads(z.read("timestamp/eidas_payload.json"))
    payload["files"]["pages/01/page.html"] = hashlib.sha256(html).hexdigest()
    praw = _canon(payload)
    man = json.loads(z.read("manifest.json"))
    man["files"]["pages/01/page.html"].update(sha256=hashlib.sha256(html).hexdigest(), size=len(html))
    man["payload_sha256"] = hashlib.sha256(praw).hexdigest()
    rep = {
        "pages/01/page.html": html,
        "timestamp/eidas_payload.json": praw,
        "timestamp/eidas_payload.sha256": (hashlib.sha256(praw).hexdigest() + "  eidas_payload.json\n").encode(),
    }
    for n in ("timestamp/eidas_payload.json", "timestamp/eidas_payload.sha256"):
        man["files"][n].update(sha256=hashlib.sha256(rep[n]).hexdigest(), size=len(rep[n]))
    rep["manifest.json"] = json.dumps(man).encode()
    r = verify_fb_zip(_rezip(src, rep))
    assert "timestamp_token" in _failed(r)
    tok = next(c for c in r.checks if c.name == "timestamp_token")
    assert "imprint" in tok.detail


def test_fb_zip_swapped_tsr_detected():
    """A genuine token from another capture must not validate this payload."""
    src = ZIP.read_bytes()
    other_tok = _pdf_token(SEALED.read_bytes())
    # wrap the other (bare) token into a TimeStampResp, as eidas.tsr is
    from asn1crypto import cms, tsp
    resp = tsp.TimeStampResp({"status": {"status": "granted"},
                              "time_stamp_token": cms.ContentInfo.load(other_tok)})
    r = verify_fb_zip(_rezip(src, {"timestamp/eidas.tsr": resp.dump()}))
    assert "timestamp_token" in _failed(r)
    assert "bundle_integrity" in _failed(r)  # manifest also catches it


def test_fb_zip_forged_tstinfo_detected():
    """Re-encoding TSTInfo with a new imprint keeps the CMS signature valid
    over the signed attributes — only the messageDigest binding catches it."""
    src = ZIP.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(src))
    from asn1crypto import cms, core, tsp
    resp = tsp.TimeStampResp.load(z.read("timestamp/eidas.tsr"))
    ci = cms.ContentInfo.load(resp["time_stamp_token"].dump())
    tst = tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
    forged = b'{"forged":true}'
    tst["message_imprint"]["hashed_message"] = hashlib.sha256(forged).digest()
    ci["content"]["encap_content_info"]["content"] = core.ParsableOctetString(tst.dump(force=True))
    resp2 = tsp.TimeStampResp({"status": resp["status"],
                               "time_stamp_token": cms.ContentInfo.load(ci.dump(force=True))})
    info = verify_token(resp2.dump(), forged)
    assert not info.ok
    assert info.signed_attr_checks.get("message_digest") == "fail"
    assert info.signed_attr_checks.get("signature") == "ok"  # the trap


def test_core_eidas_signature_rejects_forged_tstinfo():
    """Same attack against the SaaS layer (core.check_eidas_signature)."""
    from asn1crypto import cms, core, tsp
    from gpa_verify.core import check_eidas_signature
    src = ZIP.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(src))
    resp = tsp.TimeStampResp.load(z.read("timestamp/eidas.tsr"))
    ci = cms.ContentInfo.load(resp["time_stamp_token"].dump())
    tst = tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
    forged = b'{"forged":true}'
    tst["message_imprint"]["hashed_message"] = hashlib.sha256(forged).digest()
    ci["content"]["encap_content_info"]["content"] = core.ParsableOctetString(tst.dump(force=True))
    resp2 = tsp.TimeStampResp({"status": resp["status"],
                               "time_stamp_token": cms.ContentInfo.load(ci.dump(force=True))})
    bad = zipfile.ZipFile(io.BytesIO(_rezip(src, {"timestamp/eidas.tsr": resp2.dump(),
                                                  "timestamp/eidas_payload.json": forged})))
    res = check_eidas_signature(bad, {})
    assert not res.passed and "messageDigest" in res.detail


def test_fb_zip_undeclared_and_missing_files():
    src = ZIP.read_bytes()
    r = verify_fb_zip(_rezip(src, add={"pages/02/screenshot.png": b"\x89PNG fake"}))
    assert "bundle_integrity" in _failed(r)
    assert "pages" in _failed(r)  # page directory not listed in proof.json
    r = verify_fb_zip(_rezip(src, drop=("timestamp/tsl/EE.xml",)))
    assert "bundle_integrity" in _failed(r)


def test_fb_zip_unsealed_metadata_tamper_detected():
    src = ZIP.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(src))
    meta = json.loads(z.read("timestamp/eidas_meta.json"))
    meta["gen_time"] = "2026-01-01T00:00:00+00:00"
    raw = json.dumps(meta).encode()
    man = json.loads(z.read("manifest.json"))
    man["files"]["timestamp/eidas_meta.json"].update(sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    r = verify_fb_zip(_rezip(src, {"timestamp/eidas_meta.json": raw, "manifest.json": json.dumps(man).encode()}))
    assert _failed(r) == {"timestamp_metadata"}


# ═════════════════════════════════════════════════════════════════════════════
# Synthetic TSA — valid tokens over new content (multi-page, profile checks)
# ═════════════════════════════════════════════════════════════════════════════

class _TSA:
    def __init__(self, eku_critical=True, root_cn="Test Root", tsu_cn="Test TSU"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, root_cn)])
        tname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, tsu_cn),
                           x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test TSP")])
        self.root = (x509.CertificateBuilder().subject_name(rname).issuer_name(rname)
                     .public_key(self.root_key.public_key()).serial_number(1)
                     .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                     .sign(self.root_key, hashes.SHA256()))
        self.cert = (x509.CertificateBuilder().subject_name(tname).issuer_name(rname)
                     .public_key(self.key.public_key()).serial_number(2)
                     .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
                     .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), eku_critical)
                     .sign(self.root_key, hashes.SHA256()))

    def root_der(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding
        return self.root.public_bytes(Encoding.DER)

    def cert_der(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding
        return self.cert.public_bytes(Encoding.DER)

    def pem(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding
        return self.cert.public_bytes(Encoding.PEM) + self.root.public_bytes(Encoding.PEM)

    def token(self, data: bytes, gen_time=None) -> bytes:
        from asn1crypto import cms, core, tsp, x509 as ax
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import Encoding

        der = self.cert.public_bytes(Encoding.DER)
        acert = ax.Certificate.load(der)
        gen_time = gen_time or dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
        tst = tsp.TSTInfo({
            "version": "v1", "policy": "0.4.0.2023.1.1",
            "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                                "hashed_message": hashlib.sha256(data).digest()},
            "serial_number": 4242, "gen_time": gen_time,
        })
        econtent = tst.dump()
        attrs = cms.CMSAttributes([
            {"type": "content_type", "values": ["tst_info"]},
            {"type": "message_digest", "values": [hashlib.sha256(econtent).digest()]},
            {"type": "signing_certificate_v2", "values": [{"certs": [{
                "cert_hash": hashlib.sha256(der).digest()}]}]},
        ])
        sig = self.key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
        sd = cms.SignedData({
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "tst_info",
                                   "content": core.ParsableOctetString(econtent)},
            "certificates": [acert],
            "signer_infos": [{
                "version": "v1",
                "sid": {"issuer_and_serial_number": {"issuer": acert.issuer,
                                                     "serial_number": acert.serial_number}},
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": sig,
            }],
        })
        ci = cms.ContentInfo({"content_type": "signed_data", "content": sd})
        return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": ci}).dump()


def _synthetic_package(n_pages=2, tsa=None) -> bytes:
    tsa = tsa or _TSA()
    files = {}
    pages = []
    for i in range(1, n_pages + 1):
        png = b"\x89PNG page %d" % i
        html = b"<html>page %d</html>" % i
        files[f"pages/{i:02d}/screenshot.png"] = png
        files[f"pages/{i:02d}/page.html"] = html
        pages.append({"index": i, "url": f"https://example.org/{i}",
                      "screenshot_sha256": hashlib.sha256(png).hexdigest(),
                      "page_html_sha256": hashlib.sha256(html).hexdigest()})
    cm = _canon({"session_id": "sess-1", "page_count": n_pages})
    files["capture/capture_meta.json"] = cm
    files["capture/capture_meta.sha256"] = (hashlib.sha256(cm).hexdigest() + "  capture_meta.json\n").encode()
    proof = {"session_id": "sess-1", "format": "getproofanchor-lite-2", "page_count": n_pages,
             "pages": pages, "finished_at": "2026-06-01T12:00:00Z",
             "capture_meta_sha256": hashlib.sha256(cm).hexdigest(),
             "operator": {"username": "t"}, "app_version": "gpa-forensic-browser-test"}
    files["proof.json"] = _canon(proof)
    payload = _canon({"files": {k: hashlib.sha256(v).hexdigest() for k, v in files.items()},
                      "finished_at": "2026-06-01T12:00:00Z", "format": "getproofanchor-lite-2",
                      "operator_username": "t", "session_id": "sess-1"})
    sealed = dict(files)
    files["timestamp/eidas_payload.json"] = payload
    files["timestamp/eidas.tsr"] = tsa.token(payload)
    files["timestamp/tsa_certs.pem"] = tsa.pem()
    man = {"format": "getproofanchor-lite-2", "session_id": "sess-1",
           "payload_sha256": hashlib.sha256(payload).hexdigest(),
           "files": {k: {"sha256": hashlib.sha256(v).hexdigest(), "size": len(v),
                         "sealed": k in sealed} for k, v in files.items()}}
    files["manifest.json"] = json.dumps(man).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zo:
        for k, v in files.items():
            zo.writestr(k, v)
    return out.getvalue()


def test_synthetic_multipage_package_verifies():
    tsa = _TSA()
    with extra_roots([tsa.root_der()]):          # test CA trusted explicitly
        r = verify_fb_zip(_synthetic_package(3, tsa=tsa))
    assert not r.any_failed, [(c.name, c.detail, c.extra.get("failures")) for c in r.checks if c.status == "fail"]
    assert _status(r, "pages") == "pass"
    assert "3 page(s)" in next(c for c in r.checks if c.name == "pages").detail
    assert _status(r, "tsa_chain") == "pass"
    assert _status(r, "tsl_qualified") == "skip"   # no TSL bundled
    assert _status(r, "tsa_trust_root") == "pass"


def test_synthetic_package_untrusted_root_fails():
    """Same package without --trust-root: a self-made TSA must not verify."""
    r = verify_fb_zip(_synthetic_package(2))
    assert "tsa_trust_root" in _failed(r)
    assert r.summary["verdict"] == "FAILED"


def test_forged_tsa_with_forged_tsl_is_rejected():
    """Attack the pinning closes: a self-made CA named like the real SK root,
    a TSU named like the real one, and the bundled Trusted List edited to
    list the forged TSU. The TSL check alone is fooled; the pinned root is not."""
    import base64
    z = zipfile.ZipFile(io.BytesIO(ZIP.read_bytes()))
    tsl = z.read("timestamp/tsl/EE.xml")
    real_pem = [n for n in z.namelist() if n.startswith("timestamp/") and n.endswith(".pem")]
    from gpa_verify.tsp_verify import pem_to_der_list
    real_ders = [d for n in real_pem for d in pem_to_der_list(z.read(n))]
    real_b64 = [base64.b64encode(d) for d in real_ders]
    hit = next(b for b in real_b64 if b in tsl)          # the real TSU cert listed in EE.xml
    tsa = _TSA(root_cn="SK ID Solutions ROOT G1R", tsu_cn="SK TIMESTAMPING UNIT 2026R")
    forged_tsl = tsl.replace(hit, base64.b64encode(tsa.cert_der()))
    src = _synthetic_package(1, tsa=tsa)
    r = verify_fb_zip(_rezip(src, add={"timestamp/tsl/EE.xml": forged_tsl}))
    assert _status(r, "tsl_qualified") == "pass"          # fooled by the forged list …
    assert "tsa_trust_root" in _failed(r)                 # … but not by the pinned roots
    assert r.summary["verdict"] == "FAILED"


def test_trust_root_cli_option(tmp_path):
    tsa = _TSA()
    pkg = tmp_path / "pkg.zip"
    pkg.write_bytes(_synthetic_package(1, tsa=tsa))
    root = tmp_path / "root.pem"
    from cryptography.hazmat.primitives.serialization import Encoding
    root.write_bytes(tsa.root.public_bytes(Encoding.PEM))
    assert cli.main([str(pkg), "--quiet"]) == 1
    assert cli.main([str(pkg), "--quiet", "--trust-root", str(root)]) == 0
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a certificate")
    assert cli.main([str(pkg), "--quiet", "--trust-root", str(bad)]) == 2


def test_real_outputs_chain_to_pinned_sk_root():
    for data in (ZIP.read_bytes(), SEALED.read_bytes()):
        _, r = verify_bytes(data)
        c = next(c for c in r.checks if c.name == "tsa_trust_root")
        assert c.passed and c.extra["trust_root"] == "SK ID Solutions ROOT G1R", c.detail
    _, r = verify_bytes(SEALED.read_bytes())
    assert _status(r, "tsa_chain") == "pass"   # bundled SK TSA CA 2023R completes it offline


def test_pinned_fingerprints():
    from gpa_verify.trust import PINNED_FINGERPRINTS
    assert PINNED_FINGERPRINTS == {
        "d012da1a62193928c5b4d89d2a72495b1f77ea5d54f23956bc1df2f75528fefb": "SK ID Solutions ROOT G1R",
        "a272de102a8038f7e100eacfb6db1c930d3cb9f51d76b218de3a4a433bcfd182": "SK ID Solutions ROOT G1E",
        "3e84ba4342908516e77573c0992f0979ca084e4685681ff195ccba8a229b8a76": "EE Certification Centre Root CA",
    }


def test_synthetic_multipage_missing_page_artifact():
    src = _synthetic_package(2)
    z = zipfile.ZipFile(io.BytesIO(src))
    man = json.loads(z.read("manifest.json"))
    del man["files"]["pages/02/page.html"]
    bad = _rezip(src, {"manifest.json": json.dumps(man).encode()}, drop=("pages/02/page.html",))
    r = verify_fb_zip(bad)
    assert {"pages", "sealed_binding"} <= _failed(r)


def test_token_rejects_non_critical_eku():
    tsa = _TSA(eku_critical=False)
    info = verify_token(tsa.token(b"x"), b"x")
    assert not info.ok and any("critical" in e for e in info.errors)


def test_token_ok_and_wrong_data():
    tsa = _TSA()
    assert verify_token(tsa.token(b"abc"), b"abc").ok
    bad = verify_token(tsa.token(b"abc"), b"abd")
    assert not bad.ok and bad.imprint_match is False


def test_self_made_tsa_not_qualified_against_real_tsl():
    z = zipfile.ZipFile(io.BytesIO(ZIP.read_bytes()))
    tsl = z.read("timestamp/tsl/EE.xml")
    src = _synthetic_package(1)
    r = verify_fb_zip(_rezip(src, add={"timestamp/tsl/EE.xml": tsl}))
    assert _status(r, "tsl_qualified") == "fail"


# ═════════════════════════════════════════════════════════════════════════════
# PAdES sealed PDF
# ═════════════════════════════════════════════════════════════════════════════

def _byterange(pdf: bytes):
    m = re.search(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", pdf)
    return tuple(map(int, m.groups()))


def _pdf_token(pdf: bytes) -> bytes:
    a, l1, b, l2 = _byterange(pdf)
    from asn1crypto import cms
    raw = bytes.fromhex(pdf[l1 + 1:b - 1].decode())
    return cms.ContentInfo.load(raw, strict=False).dump()


def test_sealed_pdf_pristine_verifies_offline():
    r = verify_sealed_pdf(SEALED.read_bytes())
    assert not r.any_failed, [(c.name, c.detail) for c in r.checks if c.status == "fail"]
    assert r.summary["verdict"] == "VERIFIED"
    assert r.proof_id == "sess-1792572400480"
    assert _status(r, "tsl_qualified") == "skip"
    assert _status(r, "post_seal_changes") == "pass"
    assert _status(r, "attachments") == "pass"
    assert _status(r, "evidence_consistency") == "pass"
    ts = r.summary["timestamp"]
    assert ts["serial"] == "116761851795136458"
    assert ts["gen_time"].startswith("2026-10-21T08:46:43")
    names = {a["name"] for a in r.summary["attachments"]}
    assert {"manifest.json", "proof.json", "pages_01_screenshot.png"} <= names


def test_sealed_pdf_with_tsl_from_zip_is_qualified():
    _, r = verify_bytes(SEALED.read_bytes(), tsl_paths=[str(ZIP)])
    assert _status(r, "tsl_qualified") == "pass"
    assert _status(r, "tsa_chain") == "pass"   # chain certs taken from the ZIP


def test_sealed_pdf_flip_inside_byterange():
    pdf = SEALED.read_bytes()
    a, l1, b, l2 = _byterange(pdf)
    # a byte inside an embedded attachment's stream data, well inside range 1
    pos = pdf.find(b"stream", l1 // 2) + 20
    r = verify_sealed_pdf(_flip(pdf, pos))
    assert "timestamp_token" in _failed(r)
    assert r.summary["verdict"] == "FAILED"


def test_sealed_pdf_flip_in_second_range():
    pdf = SEALED.read_bytes()
    a, l1, b, l2 = _byterange(pdf)
    r = verify_sealed_pdf(_flip(pdf, b + l2 // 2))
    assert "timestamp_token" in _failed(r)


def test_sealed_pdf_flip_outside_byterange_token_part():
    pdf = SEALED.read_bytes()
    a, l1, b, l2 = _byterange(pdf)
    ba = bytearray(pdf)
    p = l1 + 1 + 200                     # inside the DER token (hex digits)
    ba[p] = ord("0") if ba[p] != ord("0") else ord("1")
    r = verify_sealed_pdf(bytes(ba))
    assert r.any_failed


def test_sealed_pdf_flip_outside_byterange_padding():
    """Zero padding of /Contents is outside the signed range; a change there
    leaves the token valid but is still reported."""
    pdf = SEALED.read_bytes()
    a, l1, b, l2 = _byterange(pdf)
    ba = bytearray(pdf)
    ba[b - 10] = ord("7")
    r = verify_sealed_pdf(bytes(ba))
    assert _status(r, "timestamp_token") == "pass"
    assert "pades_signature" in _failed(r)


def _last_startxref(pdf: bytes) -> int:
    return int(re.findall(rb"startxref\s+(\d+)", pdf)[-1])


def _append_revision(pdf: bytes, objects: dict, size: int) -> bytes:
    """Append a classic incremental update with the given {num: body} objects."""
    out = bytearray(pdf)
    if not out.endswith(b"\n"):
        out += b"\n"
    offs = {}
    for num, body in sorted(objects.items()):
        offs[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    for num in sorted(offs):
        out += b"%d 1\n%010d 00000 n \n" % (num, offs[num])
    root = re.findall(rb"/Root\s+(\d+ \d+ R)", pdf)[-1]
    info = re.findall(rb"/Info\s+(\d+ \d+ R)", pdf)[-1]
    out += (b"trailer\n<< /Size %d /Root " % size + root + b" /Info " + info
            + b" /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (_last_startxref(pdf), xref))
    return bytes(out)


def _catalog_body(pdf: bytes) -> bytes:
    doc = P.PDFDocument(pdf)
    rnum = doc.trailer["Root"].num
    off = doc.object_offset(rnum)
    start = pdf.index(b"obj", off) + 3
    end = pdf.index(b"endobj", start)
    return pdf[start:end].strip(), rnum


def test_sealed_pdf_incremental_update_modifying_info_detected():
    pdf = SEALED.read_bytes()
    doc = P.PDFDocument(pdf)
    inum = doc.trailer["Info"].num
    size = doc.trailer["Size"]
    bad = _append_revision(pdf, {inum: b"<< /Title (Forged) /Producer (x) >>"}, size)
    r = verify_sealed_pdf(bad)
    assert "post_seal_changes" in _failed(r)
    pc = next(c for c in r.checks if c.name == "post_seal_changes")
    assert "MODIFIED AFTER SEALING" in pc.detail
    assert _status(r, "timestamp_token") == "pass"   # the seal itself is still intact


def test_sealed_pdf_incremental_update_new_page_content_detected():
    pdf = SEALED.read_bytes()
    doc = P.PDFDocument(pdf)
    size = doc.trailer["Size"]
    page = doc.pages()[0]
    # find page object number
    pnum = next(n for n in doc.xref if doc.get_object(n) is not None and isinstance(doc.get_object(n), dict)
                and doc.get_object(n).get("Type") == "Page")
    pobj_off = doc.object_offset(pnum)
    body = pdf[pdf.index(b"obj", pobj_off) + 3:pdf.index(b"endobj", pobj_off)].strip()
    body = re.sub(rb"/Contents\s+\d+ 0 R", b"/Contents %d 0 R" % size, body, count=1)
    overlay = b"BT /F1 40 Tf 100 400 Td (FORGED) Tj ET"
    bad = _append_revision(pdf, {pnum: body,
                                 size: b"<< /Length %d >>\nstream\n" % len(overlay) + overlay + b"\nendstream"},
                           size + 1)
    assert page is not None
    r = verify_sealed_pdf(bad)
    assert "post_seal_changes" in _failed(r)


def test_sealed_pdf_ltv_dss_update_is_permitted():
    pdf = SEALED.read_bytes()
    doc = P.PDFDocument(pdf)
    size = doc.trailer["Size"]
    cat, rnum = _catalog_body(pdf)
    assert cat.startswith(b"<<")
    cat2 = b"<< /DSS %d 0 R" % size + cat[2:]
    z = zipfile.ZipFile(io.BytesIO(ZIP.read_bytes()))
    from gpa_verify.tsp_verify import pem_to_der_list
    certder = pem_to_der_list(z.read("timestamp/tsa_certs.pem"))[1]
    good = _append_revision(pdf, {
        rnum: cat2,
        size: b"<< /Type /DSS /Certs [ %d 0 R ] >>" % (size + 1),
        size + 1: b"<< /Length %d >>\nstream\n" % len(certder) + certder + b"\nendstream",
    }, size + 2)
    r = verify_sealed_pdf(good)
    assert not r.any_failed, [(c.name, c.detail) for c in r.checks if c.status == "fail"]
    pc = next(c for c in r.checks if c.name == "post_seal_changes")
    assert "LTV" in pc.detail


def test_sealed_pdf_garbage_appended_detected():
    r = verify_sealed_pdf(SEALED.read_bytes() + b"\n% hidden note\n1 0 obj (x) endobj\n")
    assert "post_seal_changes" in _failed(r)


def test_sealed_pdf_trailing_whitespace_tolerated():
    r = verify_sealed_pdf(SEALED.read_bytes() + b"\r\n\n")
    assert not r.any_failed


def test_sealed_pdf_text_extraction_and_attachments():
    doc = P.PDFDocument(SEALED.read_bytes())
    text = "\n".join(P.extract_text(doc))
    assert "sess-1792572400480" in text
    assert "ff38fc43e67a1a8a240fa471094bc9492170d9496db604e4b64c2a5fb4b5e915" in text


# ═════════════════════════════════════════════════════════════════════════════
# Unsealed plain copy
# ═════════════════════════════════════════════════════════════════════════════

def test_plain_copy_alone_not_verifiable():
    r = verify_plain_copy(COPY.read_bytes())
    assert r.summary["verdict"] == "NOT_VERIFIABLE"
    assert not r.any_failed
    idd = r.summary["identification"]
    assert idd["sha256"] == hashlib.sha256(SEALED.read_bytes()).hexdigest()
    assert idd["sid"] == "sess-1792572400480"
    assert idd["ts_serial"] == "116761851795136458"


def test_plain_copy_qr_matches_text():
    ident = read_copy_identification(P.PDFDocument(COPY.read_bytes()))
    qr, txt = ident["qr"], ident["text"]
    assert qr["t"] == "getproofanchor-plain-copy"
    for k in ("sid", "f", "sha256", "ts_serial"):
        assert str(qr[k]) == str(txt[k]), k


def test_plain_copy_with_original_verifies():
    r = verify_plain_copy(COPY.read_bytes(), original=SEALED.read_bytes(),
                          original_name=SEALED.name)
    assert r.summary["verdict"] == "VERIFIED", [(c.name, c.detail) for c in r.checks if c.status == "fail"]
    assert _status(r, "copy_binding") == "pass"
    assert _status(r, "copy_content_consistency") == "pass"
    assert _status(r, "copy_integrity") == "skip"
    assert any("NOT PROVEN" in n for n in r.summary["notes"])


def test_plain_copy_with_tampered_original_fails():
    pdf = SEALED.read_bytes()
    a, l1, b, l2 = _byterange(pdf)
    r = verify_plain_copy(COPY.read_bytes(), original=_flip(pdf, l1 // 3))
    assert {"copy_binding", "original.timestamp_token"} <= _failed(r)


def test_plain_copy_with_wrong_original_fails():
    r = verify_plain_copy(COPY.read_bytes(), original=SEALED.read_bytes() + b"\n")
    assert "copy_binding" in _failed(r)


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def test_cli_exit_codes(capsys, tmp_path):
    assert cli.main(["--no-color", str(ZIP)]) == 0
    assert cli.main(["--no-color", str(SEALED)]) == 0
    assert cli.main(["--no-color", str(COPY)]) == 3
    assert cli.main(["--no-color", str(COPY), "--original", str(SEALED), "--tsl", str(ZIP)]) == 0
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(SEALED.read_bytes() + b"garbage that is not a revision")
    assert cli.main(["--quiet", str(bad)]) == 1
    assert cli.main([str(COPY), "--original", str(tmp_path / "missing.pdf")]) == 2
    capsys.readouterr()


def test_cli_json(capsys):
    assert cli.main(["--json", str(SEALED), "--tsl", str(ZIP)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["verdict"] == "VERIFIED"
    assert out["bundle_format"].startswith("forensic-browser-pades")
    assert {c["name"] for c in out["checks"]} >= {"pades_signature", "timestamp_token", "tsl_qualified"}
