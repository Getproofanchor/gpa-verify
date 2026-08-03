"""Tampering with certified files must be detected.

Regression tests for the gap fixed in 1.5.0: versions up to 1.4.0 never
examined files_manifest.json or the preserved bytes under files/, so a bundle
whose certified digest or file contents had been swapped still verified. The
manifest.json index is not covered by the qualified timestamp, so an attacker
can recompute it freely — every assertion here therefore anchors on
capture_meta.json and content.txt, which are sealed.
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


def _file_digest_bundles():
    for p in sorted(FIXTURES.glob("*.zip")):
        with zipfile.ZipFile(p) as zf:
            try:
                proof = json.loads(zf.read("proof.json"))
            except KeyError:
                continue
        if (proof.get("capture") or {}).get("mode") == "file_digest":
            yield p


BUNDLES = list(_file_digest_bundles())
needs_bundle = pytest.mark.skipif(
    not BUNDLES, reason="no file-digest fixture available"
)


def _rebuild(src: Path, mutate) -> bytes:
    """Rebuild a bundle after mutating members, recomputing manifest.json.

    Recomputing the index is what a competent tamperer would do, so a test
    that skips it would prove nothing.
    """
    with zipfile.ZipFile(src) as zf:
        members = {i.filename: zf.read(i.filename) for i in zf.infolist()}
    mutate(members)
    manifest = json.loads(members["manifest.json"])
    manifest["files"] = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for name, data in members.items()
        if name != "manifest.json"
    }
    members["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name, data in members.items():
            out.writestr(name, data)
    return buf.getvalue()


def _check(report, name):
    return next(c for c in report.checks if c.name == name)


@needs_bundle
@pytest.mark.parametrize("bundle", BUNDLES, ids=lambda p: p.name[:24])
def test_untouched_bundle_passes(bundle):
    report = verify_evidence_zip(bundle.read_bytes())
    assert _check(report, "file_digest").passed


@needs_bundle
@pytest.mark.parametrize("bundle", BUNDLES, ids=lambda p: p.name[:24])
def test_swapped_digest_is_detected(bundle):
    def mutate(members):
        fm = json.loads(members["files_manifest.json"])
        fm["files"][0]["sha256"] = "deadbeef" * 8
        members["files_manifest.json"] = json.dumps(
            fm, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()

    report = verify_evidence_zip(_rebuild(bundle, mutate))
    check = _check(report, "file_digest")
    assert not check.passed and not check.skipped
    assert report.any_failed


@needs_bundle
@pytest.mark.parametrize("bundle", BUNDLES, ids=lambda p: p.name[:24])
def test_swapped_retained_contents_are_detected(bundle):
    with zipfile.ZipFile(bundle) as zf:
        if not any(n.startswith("files/") for n in zf.namelist()):
            pytest.skip("bundle retains no file contents")

    def mutate(members):
        key = next(k for k in members if k.startswith("files/"))
        members[key] = b"SUBSTITUTED CONTENT" * 100

    report = verify_evidence_zip(_rebuild(bundle, mutate))
    check = _check(report, "file_digest")
    assert not check.passed and not check.skipped
    assert report.any_failed


@needs_bundle
@pytest.mark.parametrize("bundle", BUNDLES, ids=lambda p: p.name[:24])
def test_missing_files_manifest_is_detected(bundle):
    def mutate(members):
        del members["files_manifest.json"]

    report = verify_evidence_zip(_rebuild(bundle, mutate))
    check = _check(report, "file_digest")
    assert not check.passed and not check.skipped