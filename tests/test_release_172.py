"""
1.7.2 — Forensic Browser 1.6.0 "Video & audio" (media/NN/).

Fixtures in tests/fixtures/forensic_browser/media/ are real outputs of the app
(see make_fixtures.py there): a ZIP package with an original MP4 and a playback
recording, and a dual_pdf whose media exceeded the PDF limit and travel in a
companion archive (…_media.zip). Self-made test TSA: only trust anchoring can
fail.

What 1.7.1 already verified unchanged: the ZIP package (media files are ordinary
sealed files) and the sealed PDF with embedded media. New in 1.7.2:
  - external_media: the companion archive is checked against the SHA-256
    values sealed in the PDF (--media); without it the check is skipped and the
    report says the media were not checked
  - the plain copy may print the address of the page a media item came from
    (proof.json media[].page_url) and the digests of external media
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from gpa_verify import verify_bytes
from gpa_verify.cli import main as cli_main
from gpa_verify.forensic_browser import (_check_external_media, _external_files, verify_plain_copy,
                                         verify_sealed_pdf)

D = Path(__file__).parent / "fixtures" / "forensic_browser" / "media"
ZIP, PDF, COPY, MEDIA = (D / "media-zip.zip", D / "media-dual_pdf.pdf",
                         D / "media-dual_pdf_bez-pecete.pdf", D / "media-dual_pdf_media.zip")
pytestmark = pytest.mark.skipif(not all(p.exists() for p in (ZIP, PDF, COPY, MEDIA)),
                                reason="media fixtures missing")
TRUST = {"tsa_trust_root", "tsl_qualified", "original.tsa_trust_root", "original.tsl_qualified",
         "copy_integrity"}


def _failed(rep):
    return {c.name for c in rep.checks if not c.passed and not c.skipped} - TRUST


def _check(rep, name):
    return next(c for c in rep.checks if c.name == name)


def _rezip(src: bytes, replace=None, drop=()):
    zin = zipfile.ZipFile(io.BytesIO(src))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zo:
        for n in zin.namelist():
            if n in drop:
                continue
            zo.writestr(n, (replace or {}).get(n, zin.read(n)))
    return out.getvalue()


def test_zip_with_media():
    kind, rep = verify_bytes(ZIP.read_bytes())
    assert kind == "fb_zip" and not _failed(rep), _failed(rep)
    sealed = _check(rep, "sealed_binding").extra["sealed_files"]
    assert "media/01/video.mp4" in sealed and "media/02/recording.webm" in sealed
    assert "media/01/media.json" in sealed and "media/01/frames/video_1.jpg" in sealed


def test_zip_media_tamper_detected():
    raw = ZIP.read_bytes()
    zf = zipfile.ZipFile(io.BytesIO(raw))
    v = bytearray(zf.read("media/01/video.mp4"))
    v[5000] ^= 0xFF
    _, rep = verify_bytes(_rezip(raw, {"media/01/video.mp4": bytes(v)}))
    assert "sealed_binding" in _failed(rep) and "bundle_integrity" in _failed(rep)


def test_pdf_external_without_media_zip():
    rep = verify_sealed_pdf(PDF.read_bytes())
    assert not _failed(rep), _failed(rep)
    c = _check(rep, "external_media")
    assert c.skipped and "--media" in c.detail
    assert len(c.extra["external_files"]) == 4
    assert any("NOT checked" in n for n in rep.summary.get("notes", []))


def test_pdf_external_with_media_zip():
    kind, rep = verify_bytes(PDF.read_bytes(), media=MEDIA.read_bytes())
    assert kind == "sealed_pdf" and not _failed(rep), _failed(rep)
    c = _check(rep, "external_media")
    assert c.passed and c.detail.startswith("4/4")


def test_pdf_external_media_tampered_or_missing():
    raw = MEDIA.read_bytes()
    zf = zipfile.ZipFile(io.BytesIO(raw))
    v = bytearray(zf.read("media/01/video.mp4"))
    v[100] ^= 1
    rep = verify_sealed_pdf(PDF.read_bytes(), media_zip=_rezip(raw, {"media/01/video.mp4": bytes(v)}))
    c = _check(rep, "external_media")
    assert not c.passed and c.extra["failures"][0]["file"] == "media/01/video.mp4"
    rep = verify_sealed_pdf(PDF.read_bytes(), media_zip=_rezip(raw, drop={"media/02/stream_400.ts"}))
    assert "missing" in _check(rep, "external_media").extra["failures"][0]["error"]
    rep = verify_sealed_pdf(PDF.read_bytes(), media_zip=b"not a zip")
    assert not _check(rep, "external_media").passed


def test_plain_copy_with_media_from_uncaptured_page():
    rep = verify_plain_copy(COPY.read_bytes(), original=PDF.read_bytes(), original_name=PDF.name)
    assert not _failed(rep), [(c.name, c.detail) for c in rep.checks if c.name in _failed(rep)]
    assert _check(rep, "copy_content_consistency").passed


def test_external_files_shape_and_text_digest():
    good = {"sha256": "a" * 64, "size": 3, "container": "x_media.zip"}
    m = {"external_files": {"media/01/v.mp4": good, "../x": good, "media/../x": good,
                            "media/02/v.mp4": {"sha256": "zz", "size": 1}, "media/03/v.mp4": {"sha256": "b" * 64}}}
    assert list(_external_files(m)) == ["media/01/v.mp4"]
    assert _external_files({"external_files": []}) == {}
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:
        z.writestr("media/01/v.mp4", b"abc")
    ok = _check_external_media({"media/01/v.mp4": {"sha256": hashlib.sha256(b"abc").hexdigest(), "size": 3}},
                               data.getvalue())
    assert ok.passed


def test_cli_media_option(tmp_path, capsys):
    rc = cli_main([str(PDF), "--media", str(MEDIA), "--json"])
    out = json.loads(capsys.readouterr().out)
    ext = [c for c in out["checks"] if c["name"] == "external_media"][0]
    assert ext["status"] == "pass" and rc == 1    # self-made TSA: tsa_trust_root fails
    rc = cli_main([str(ZIP), "--media", str(MEDIA), "--quiet"])
    assert "--media is ignored" in capsys.readouterr().err
    assert cli_main([str(PDF), "--media", str(tmp_path / "nope.zip")]) == 2
