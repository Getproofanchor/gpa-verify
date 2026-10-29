"""
1.7.3 — the companion media archive (…_media.zip) given on its own.

Before 1.7.3 `gpa-verify GetProofAnchor_sess-…_media.zip` ended in
"FAILED manifest_load" (the archive has no manifest.json — it is not evidence
by itself). Now it is recognised (README.txt title + only media/ entries):
  - alone → NOT VERIFIABLE BY ITSELF (exit 3) with the exact command to run
  - with --original <sealed PDF> → the same as `<pdf> --media <this archive>`
  - with --original <plain copy or anything else> → FAILED (original_kind)
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from gpa_verify import verify_bytes
from gpa_verify.cli import main as cli_main
from gpa_verify.dispatch import detect_kind

D = Path(__file__).parent / "fixtures" / "forensic_browser" / "media"
PDF, COPY, MEDIA = (D / "media-dual_pdf.pdf", D / "media-dual_pdf_bez-pecete.pdf",
                    D / "media-dual_pdf_media.zip")
pytestmark = pytest.mark.skipif(not all(p.exists() for p in (PDF, COPY, MEDIA)),
                                reason="media fixtures missing")
TRUST = {"tsa_trust_root", "tsl_qualified"}


def _zip(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zo:
        for n, b in entries.items():
            zo.writestr(n, b)
    return out.getvalue()


def test_detected_as_companion():
    assert detect_kind(MEDIA.read_bytes()) == "fb_media_zip"


def test_alone_not_verifiable_with_command():
    kind, rep = verify_bytes(MEDIA.read_bytes())
    assert kind == "fb_media_zip"
    s = rep.summary
    assert s["verdict"] == "NOT_VERIFIABLE" and s["checks_failed"] == 0
    assert rep.checks[0].name == "media_companion" and rep.checks[0].skipped
    assert any(n.startswith("Run: gpa-verify ") and "--media" in n for n in s["notes"])
    assert s.get("sealed_document", "").endswith(".pdf")
    assert rep.proof_id and rep.proof_id.startswith("sess-")


def test_with_original_sealed_pdf_equals_media_option():
    _, a = verify_bytes(MEDIA.read_bytes(), original=PDF.read_bytes())
    _, b = verify_bytes(PDF.read_bytes(), media=MEDIA.read_bytes())
    names = lambda r: {c.name: (c.passed, c.skipped) for c in r.checks}
    assert names(a) == names(b)
    em = next(c for c in a.checks if c.name == "external_media")
    assert em.passed and not em.skipped
    assert {c.name for c in a.checks if not c.passed and not c.skipped} <= TRUST
    assert any(n.startswith("Verified as:") for n in a.summary["notes"])


def test_with_original_plain_copy_fails_clearly():
    _, rep = verify_bytes(MEDIA.read_bytes(), original=COPY.read_bytes())
    assert rep.summary["verdict"] == "FAILED"
    c = rep.checks[0]
    assert c.name == "original_kind" and not c.passed and "sealed PDF" in str(c.detail)


def test_not_a_companion():
    title = b"GetProofAnchor Forensic Browser \xe2\x80\x94 companion media archive\n"
    # README with the title, but another entry outside media/
    assert detect_kind(_zip({"README.txt": title, "media/01/a.mp4": b"x", "evil.txt": b"x"})) == "zip_unknown"
    # media/ only, but a different README
    assert detect_kind(_zip({"README.txt": b"hello", "media/01/a.mp4": b"x"})) == "zip_unknown"
    # no media entries at all
    assert detect_kind(_zip({"README.txt": title})) == "zip_unknown"
    # proper shape
    assert detect_kind(_zip({"README.txt": title, "media/01/a.mp4": b"x"})) == "fb_media_zip"


def test_cli_exit_codes(capsys):
    assert cli_main([str(MEDIA)]) == 3
    assert "NOT VERIFIABLE" in capsys.readouterr().out
    assert cli_main(["--quiet", str(MEDIA)]) == 3
    assert "--media" in capsys.readouterr().err
    assert cli_main([str(MEDIA), "--original", str(COPY)]) == 1
