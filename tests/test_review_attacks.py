"""
Regression tests for the 1.6.0 pre-release review (R1–R3, N8):

* R1  post-seal updates may only add a genuine Document Security Store —
      a DSS that points at page objects or content must not make a forged
      page "permitted";
* R2  the TSA chain must pass through CA certificates only, and under the
      pinned roots the TSA must be issued by a time-stamping CA;
* R3  hostile PDFs / ZIPs must be refused quickly and with bounded memory;
* N8  duplicate ZIP member names are rejected.

All attack files are generated in memory from the real sealed fixture.
"""

from __future__ import annotations

import datetime as dt
import io
import time
import zipfile
import zlib
from pathlib import Path

import pytest

from gpa_verify import pdfmini as P
from gpa_verify import trust
from gpa_verify.dispatch import verify_bytes
from gpa_verify.forensic_browser import verify_sealed_pdf
from gpa_verify.trust import check_trust_root, extra_roots

FB = Path(__file__).parent / "fixtures" / "forensic_browser"
SEALED = FB / "GetProofAnchor_sess-1792572400480.pdf"
FBZIP = FB / "GetProofAnchor_sess-1792572420814.zip"


# ─── tiny incremental-update writer ─────────────────────────────────────────

def _ser(o) -> bytes:
    if isinstance(o, P.Ref):
        return f"{o.num} {o.gen} R".encode()
    if isinstance(o, bool):
        return b"true" if o else b"false"
    if o is None:
        return b"null"
    if isinstance(o, P.Name):
        return b"/" + str(o).encode("latin-1")
    if isinstance(o, P.PDFString):
        return b"<" + bytes(o).hex().encode() + b">"
    if isinstance(o, (int, float)):
        return str(o).encode()
    if isinstance(o, dict):
        return b"<<" + b" ".join(b"/" + k.encode("latin-1") + b" " + _ser(v) for k, v in o.items()) + b">>"
    if isinstance(o, list):
        return b"[" + b" ".join(_ser(x) for x in o) + b"]"
    if isinstance(o, bytes):
        return o
    raise TypeError(type(o))


def _stream(body: bytes, extra: bytes = b"") -> bytes:
    return b"<</Length " + str(len(body)).encode() + extra + b">>\nstream\n" + body + b"\nendstream"


def _update(data: bytes, objs: dict, root: int = None) -> bytes:
    doc = P.PDFDocument(data)
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    offs = {}
    for n, body in sorted(objs.items()):
        offs[n] = len(out)
        out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
    xo = len(out)
    out += b"xref\n"
    for n in sorted(offs):
        out += f"{n} 1\n{offs[n]:010d} 00000 n \n".encode()
    prev = int(data[data.rfind(b"startxref") + 9:].split()[0])
    tr = {"Size": max(int(doc.trailer["Size"]), max(offs) + 1),
          "Root": P.Ref(root, 0) if root else doc.trailer["Root"],
          "Info": doc.trailer["Info"], "Prev": prev}
    out += b"trailer\n" + _ser(tr) + b"\nstartxref\n" + str(xo).encode() + b"\n%%EOF\n"
    return bytes(out)


def _post_seal(r):
    return next(c for c in r.checks if c.name == "post_seal_changes")


@pytest.fixture(scope="module")
def sealed():
    data = SEALED.read_bytes()
    doc = P.PDFDocument(data)
    return data, doc


# ─── R1 ─────────────────────────────────────────────────────────────────────

def test_legit_dss_update_still_verifies(sealed):
    data, doc = sealed
    root = dict(doc.root)
    root["DSS"] = P.Ref(48, 0)
    upd = _update(data, {
        47: _stream(b"0\x82fake-cert-der"),
        48: b"<</Type/DSS/Certs[47 0 R]>>",
        3: _ser(root),
    })
    r = verify_sealed_pdf(upd)
    assert _post_seal(r).passed, _post_seal(r).detail
    assert r.summary["verdict"] == "VERIFIED"


def test_dss_smuggling_a_forged_page_is_rejected(sealed):
    """Reviewer's A_dss_smuggle_page: new content stream referenced from the
    page AND listed in /DSS, page object listed in /DSS too."""
    data, doc = sealed
    page = dict(doc.get_object(4))
    page["Contents"] = [P.Ref(5, 0), P.Ref(47, 0)]
    root = dict(doc.root)
    root["DSS"] = P.Ref(48, 0)
    upd = _update(data, {
        4: _ser(page),
        47: _stream(b"1 1 1 rg 0 0 595 842 re f BT /F1 40 Tf 0 0 0 rg 50 400 Td (FORGED BY ATTACKER) Tj ET"),
        48: b"<</Type/DSS/Certs[4 0 R 47 0 R]>>",
        3: _ser(root),
    })
    r = verify_sealed_pdf(upd)
    assert not _post_seal(r).passed
    assert r.summary["verdict"] == "FAILED"


def test_dss_stream_reused_as_page_content_is_rejected(sealed):
    """Content stream listed only in a valid DSS, page changed to show it."""
    data, doc = sealed
    page = dict(doc.get_object(4))
    page["Contents"] = P.Ref(47, 0)
    root = dict(doc.root)
    root["DSS"] = P.Ref(48, 0)
    upd = _update(data, {
        4: _ser(page),
        47: _stream(b"BT (forged) Tj ET"),
        48: b"<</Type/DSS/Certs[47 0 R]>>",
        3: _ser(root),
    })
    assert not _post_seal(verify_sealed_pdf(upd)).passed


def test_new_catalog_object_via_dss_is_rejected(sealed):
    data, doc = sealed
    root = dict(doc.root)
    root["DSS"] = P.Ref(48, 0)
    root["OpenAction"] = P.Ref(4, 0)
    upd = _update(data, {
        47: _stream(b"0\x82x"),
        48: b"<</Type/DSS/Certs[47 0 R]>>",
        49: _ser(root),
    }, root=49)
    assert not _post_seal(verify_sealed_pdf(upd)).passed


def test_dss_with_foreign_keys_is_rejected(sealed):
    data, doc = sealed
    root = dict(doc.root)
    root["DSS"] = P.Ref(48, 0)
    upd = _update(data, {
        47: _stream(b"0\x82x"),
        48: b"<</Type/DSS/Certs[47 0 R]/Pages 2 0 R>>",
        3: _ser(root),
    })
    assert not _post_seal(verify_sealed_pdf(upd)).passed


def test_catalog_acroform_swap_is_rejected(sealed):
    data, doc = sealed
    root = dict(doc.root)
    root["AcroForm"] = P.Ref(47, 0)
    upd = _update(data, {47: b"<</Fields[]/XFA 5 0 R>>", 3: _ser(root)})
    assert not _post_seal(verify_sealed_pdf(upd)).passed


# ─── R2 ─────────────────────────────────────────────────────────────────────

def _name(cn):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pub, key, *, ca, path_len=None, eku_ts=False, key_cert_sign=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID

    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), True))
    if key_cert_sign is not None:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=not key_cert_sign, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
            crl_sign=key_cert_sign, encipher_only=False, decipher_only=False), True)
    if eku_ts:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True)
    return b.sign(key, hashes.SHA256())


def _key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


def _der(c):
    from cryptography.hazmat.primitives.serialization import Encoding
    return c.public_bytes(Encoding.DER)


AT = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)


def test_chain_through_end_entity_cert_is_rejected():
    rk, ek, tk = _key(), _key(), _key()
    root = _cert("Root", "Root", rk.public_key(), rk, ca=True, key_cert_sign=True)
    ee = _cert("Person", "Root", ek.public_key(), rk, ca=False, key_cert_sign=False)
    tsa = _cert("Fake TSA", "Person", tk.public_key(), ek, ca=False, eku_ts=True)
    with extra_roots([_der(root)]):
        r = check_trust_root(_der(tsa), [_der(ee)], AT)
    assert not r.passed


def test_path_length_constraint_enforced():
    rk, ak, bk, tk = _key(), _key(), _key(), _key()
    root = _cert("Root", "Root", rk.public_key(), rk, ca=True, key_cert_sign=True)
    a = _cert("CA A", "Root", ak.public_key(), rk, ca=True, path_len=0, key_cert_sign=True)
    b = _cert("CA B", "CA A", bk.public_key(), ak, ca=True, key_cert_sign=True)
    tsa = _cert("TSA", "CA B", tk.public_key(), bk, ca=False, eku_ts=True)
    with extra_roots([_der(root)]):
        assert not check_trust_root(_der(tsa), [_der(a), _der(b)], AT).passed
        tsa2 = _cert("TSA", "CA A", tk.public_key(), ak, ca=False, eku_ts=True)
        assert check_trust_root(_der(tsa2), [_der(a)], AT).passed


def test_pinned_root_requires_time_stamping_ca(monkeypatch):
    """Under a pinned (not user-supplied) root, a TSA issued by any CA other
    than the pinned time-stamping CA must fail — e.g. an ID-card CA."""
    rk, tsak, idk, tk = _key(), _key(), _key(), _key()
    root = _cert("Pinned Root", "Pinned Root", rk.public_key(), rk, ca=True, key_cert_sign=True)
    tsa_ca = _cert("TSA CA", "Pinned Root", tsak.public_key(), rk, ca=True, path_len=0, key_cert_sign=True)
    id_ca = _cert("ID CA", "Pinned Root", idk.public_key(), rk, ca=True, path_len=0, key_cert_sign=True)
    from cryptography.hazmat.primitives.serialization import Encoding
    monkeypatch.setattr(trust, "PINNED_ROOTS", [("Pinned Root", _der(root))])
    monkeypatch.setattr(trust, "KNOWN_INTERMEDIATES", [_der(tsa_ca)])
    monkeypatch.setattr(trust, "_KNOWN_INTERMEDIATES",
                        (("TSA CA", "x", tsa_ca.public_bytes(Encoding.PEM).decode()),))
    good = _cert("TSU", "TSA CA", tk.public_key(), tsak, ca=False, eku_ts=True)
    bad = _cert("TSU", "ID CA", tk.public_key(), idk, ca=False, eku_ts=True)
    assert check_trust_root(_der(good), [], AT).passed
    r = check_trust_root(_der(bad), [_der(id_ca)], AT)
    assert not r.passed and "not an SK time-stamping CA" in r.detail
    no_eku = _cert("TSU", "TSA CA", tk.public_key(), tsak, ca=False, eku_ts=False)
    assert not check_trust_root(_der(no_eku), [], AT).passed


# ─── R3 ─────────────────────────────────────────────────────────────────────

def _quick(data: bytes, limit: float = 10.0):
    t = time.monotonic()
    _, r = verify_bytes(data)
    assert time.monotonic() - t < limit
    return r


def test_byterange_spam_is_fast():
    body = b"".join(b"%d 0 obj <</ByteRange [0 1 2 3]>> endobj\n" % i for i in range(1, 20001))
    r = _quick(b"%PDF-1.7\n" + body + b"%%EOF\n")
    assert r.summary["verdict"] == "FAILED"


def test_predictor_columns_bomb_is_fast():
    raw = zlib.compress(b"\x00" * 100)
    stm = (b"1 0 obj <</Length %d/Filter/FlateDecode/DecodeParms<</Predictor 12/Columns 2000000000>>>>"
           b"stream\n" % len(raw)) + raw + b"\nendstream endobj\n"
    with pytest.raises(P.PDFError):
        P.decode_stream(P.Parser(stm, resolver=None).parse_indirect_at(0)[2])
    _quick(b"%PDF-1.7\n" + stm + b"%%EOF\n")


def test_flate_bomb_is_bounded():
    bomb = zlib.compress(b"\x00" * (P.MAX_STREAM_DECODED + 1024), 9)
    stm = P.Stream({"Filter": P.Name("FlateDecode"), "Length": len(bomb)}, bomb)
    with pytest.raises(P.LimitExceeded):
        P.decode_stream(stm)


def test_xref_stream_zero_width_rejected():
    with pytest.raises(P.PDFError):
        doc = P.PDFDocument.__new__(P.PDFDocument)
        doc._read_xref_stream(0, P.Stream({"W": [0, 0, 0], "Size": 10 ** 9}, b""))


# ─── N8 / ZIP limits ────────────────────────────────────────────────────────

def test_duplicate_member_names_rejected():
    src = zipfile.ZipFile(io.BytesIO(FBZIP.read_bytes()))
    out = io.BytesIO()
    import warnings
    with zipfile.ZipFile(out, "w") as z, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for i in src.infolist():
            z.writestr(i, src.read(i))
        z.writestr("proof.json", b"{}")
    _, r = verify_bytes(out.getvalue())
    assert r.summary["verdict"] == "FAILED"
    assert any(c.name == "zip_structure" and not c.passed for c in r.checks)


def test_zip_bomb_member_rejected_before_reading():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", b'{"format":"x"}')
        z.writestr("big.bin", b"\x00" * (40 << 20))
    _, r = verify_bytes(out.getvalue())
    assert any(c.name == "zip_structure" and not c.passed for c in r.checks)
