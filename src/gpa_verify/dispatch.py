"""
gpa_verify.dispatch — auto-detect the input kind and route it.

  SaaS evidence ZIP            → core.verify_evidence_zip
  Forensic Browser ZIP         → forensic_browser.verify_fb_zip
  PAdES sealed PDF             → forensic_browser.verify_sealed_pdf
  Unsealed plain copy PDF      → forensic_browser.verify_plain_copy
  Unsealed package report PDF  → forensic_browser.verify_fb_report
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import List, Optional, Tuple

from .core import CheckResult, VerifyReport


def detect_kind(data: bytes) -> str:
    """Return one of: saas_zip, fb_zip, zip_unknown, sealed_pdf, plain_copy,
    fb_report, pdf_unsigned, unknown."""
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return "zip_unknown"
        from .forensic_browser import is_fb_manifest

        def _j(n):
            try:
                o = json.loads(zf.read(n).decode("utf-8"))
                return o if isinstance(o, dict) else None
            except Exception:
                return None
        man, proof = _j("manifest.json"), _j("proof.json")
        if man is None:
            return "zip_unknown"
        return "fb_zip" if is_fb_manifest(man, proof) else "saas_zip"
    if b"%PDF-" in data[:1024]:
        from . import pdfmini as P
        from .forensic_browser import classify_pdf
        try:
            doc = P.PDFDocument(data)
            c = classify_pdf(doc)
        except Exception:
            # unparsable: still route by the strongest marker present
            return "sealed_pdf" if b"/ByteRange" in data else "pdf_unsigned"
        return {"sealed": "sealed_pdf", "plain_copy": "plain_copy",
                "fb_report": "fb_report"}.get(c, "pdf_unsigned")
    return "unknown"


def verify_bytes(
    data: bytes,
    *,
    original: Optional[bytes] = None,
    original_name: Optional[str] = None,
    tsl_paths: Optional[List[str]] = None,
    cert_paths: Optional[List[str]] = None,
    bitcoin_rpc: Optional[str] = None,
) -> Tuple[str, VerifyReport]:
    """Verify any supported GetProofAnchor output. Returns (kind, report)."""
    from . import forensic_browser as FB

    kind = detect_kind(data)
    tsl, certs = FB.load_trust_inputs(tsl_paths or [], cert_paths or [])
    try:
        rep = _route(kind, data, original, original_name, tsl, certs, bitcoin_rpc)
        if not rep.summary:  # core returns an empty summary when the ZIP is unusable
            rep.summary = {"checks_total": len(rep.checks),
                           "checks_passed": sum(1 for c in rep.checks if c.passed),
                           "checks_failed": sum(1 for c in rep.checks if not c.passed and not c.skipped),
                           "checks_skipped": sum(1 for c in rep.checks if c.skipped),
                           "verdict": "FAILED"}
        return kind, rep
    except Exception as exc:  # last-resort safety net: never crash on hostile input
        rep = VerifyReport(bundle_format=kind)
        rep.checks.append(CheckResult(
            "internal_error", False, detail=f"verification aborted: {type(exc).__name__}: {exc}"))
        rep.summary = {"checks_total": 1, "checks_passed": 0, "checks_failed": 1,
                       "checks_skipped": 0, "verdict": "FAILED"}
        return kind, rep


def _route(kind, data, original, original_name, tsl, certs, bitcoin_rpc) -> VerifyReport:
    from . import forensic_browser as FB
    from .core import verify_evidence_zip

    if kind in ("saas_zip", "zip_unknown"):
        return verify_evidence_zip(data, bitcoin_rpc=bitcoin_rpc)
    if kind == "fb_zip":
        return FB.verify_fb_zip(data)
    if kind == "sealed_pdf":
        return FB.verify_sealed_pdf(data, tsl_files=tsl, extra_certs=certs)
    if kind == "plain_copy":
        return FB.verify_plain_copy(data, original=original, original_name=original_name,
                                    tsl_files=tsl, extra_certs=certs)
    if kind == "fb_report":
        return FB.verify_fb_report(data, original=original)
    rep = VerifyReport(bundle_format="unknown")
    rep.checks.append(CheckResult(
        "input_format", False,
        detail=("PDF without any signature, time-stamp or GetProofAnchor identification"
                if kind == "pdf_unsigned" else "not a ZIP or PDF file")))
    rep.summary = {"checks_total": 1, "checks_passed": 0, "checks_failed": 1,
                   "checks_skipped": 0, "verdict": "FAILED"}
    return rep
