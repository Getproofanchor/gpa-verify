"""
gpa-verify — independent verifier for GetProofAnchor evidence bundles.

This package is the reference implementation of the verification protocol
documented at https://getproofanchor.com/verify. It does NOT depend on
any GetProofAnchor server — given an evidence ZIP and the bundled
artifacts, it produces a deterministic verdict.
"""

__version__ = "1.5.0"

from .core import (
    CheckResult,
    VerifyReport,
    verify_evidence_zip,
)
from .dispatch import detect_kind, verify_bytes
from .forensic_browser import verify_fb_zip, verify_plain_copy, verify_sealed_pdf

__all__ = [
    "CheckResult",
    "VerifyReport",
    "__version__",
    "detect_kind",
    "verify_bytes",
    "verify_evidence_zip",
    "verify_fb_zip",
    "verify_plain_copy",
    "verify_sealed_pdf",
]
