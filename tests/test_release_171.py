"""Tests for gpa-verify 1.7.1 (audit 01-D1, 01-D2, 01-D6, 01-D10, 01 N16, rv-O1).

All tampered packages are built here from the fixtures already in
tests/fixtures/ — no new evidence files are committed.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from gpa_verify import cli, detect_kind, verify_bytes, verify_evidence_zip
from gpa_verify.core import (
    BROWSER_CAPTURE_NOTE,
    _capture_mode_problems,
    _norm_time,
    check_unlisted_files,
    sealed_capture_mode,
)

FIXTURES = Path(__file__).parent / "fixtures"
SERVER = FIXTURES / "GetProofAnchor_Evidence_aeb2b103-d7c5-441c-b540-c0df600a34cf.zip"
FILE_DIGEST = FIXTURES / "fx_2165a04f-5e6c-4cf0-a5d3-00f232584b9a.zip"
NO_TSR = FIXTURES / "v3" / "fx_v3_server_no_inclusion.zip"
FB_ZIP = FIXTURES / "forensic_browser" / "GetProofAnchor_sess-1792572420814.zip"
SAAS_ZIPS = sorted(FIXTURES.glob("*.zip"))


def _check(report, name):
    return next(c for c in report.checks if c.name == name)


def _files(data: bytes):
    z = zipfile.ZipFile(io.BytesIO(data))
    return {n: z.read(n) for n in z.namelist()}


def _write(files, *, recompute_manifest=True) -> bytes:
    files = dict(files)
    if recompute_manifest:
        man = json.loads(files["manifest.json"])
        man["files"] = {k: {"sha256": hashlib.sha256(v).hexdigest(), "size": len(v)}
                        for k, v in files.items() if k != "manifest.json"}
        files["manifest.json"] = json.dumps(man, indent=2).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(k, v)
    return out.getvalue()


def _edit_proof(data: bytes, fn) -> bytes:
    files = _files(data)
    proof = json.loads(files["proof.json"])
    fn(proof)
    files["proof.json"] = json.dumps(proof, indent=2).encode()
    return _write(files)


def _downgrade_full(data: bytes) -> bytes:
    """adv/ext/downgrade_full: drop timestamp/, edit screenshot and content,
    remove every eidas/status marker from proof.json and manifest.json and
    recompute everything a forger can recompute."""
    files = {k: v for k, v in _files(data).items() if not k.startswith("timestamp/")}
    shot = bytearray(files["screenshot.png"])
    shot[-20] ^= 1
    files["screenshot.png"] = bytes(shot)
    files["content.txt"] += b"\nFORGED LINE\n"
    proof = json.loads(files["proof.json"])
    for k in list(proof):
        if k.startswith("eidas") or k == "status":
            proof.pop(k)
    proof["screenshot_sha256"] = hashlib.sha256(files["screenshot.png"]).hexdigest()
    proof["content_sha256"] = hashlib.sha256(files["content.txt"]).hexdigest()
    files["proof.json"] = json.dumps(proof, indent=2).encode()
    man = json.loads(files["manifest.json"])
    man.pop("eidas", None)
    man.pop("status", None)
    files["manifest.json"] = json.dumps(man).encode()
    return _write(files)


def _cli(tmp_path, data: bytes, *args, name="bundle.zip"):
    p = tmp_path / name
    p.write_bytes(data)
    return cli.main(["--no-color", str(p), *args])


# ─── 01-D1: no verified qualified timestamp → never VERIFIED ───────────────

def test_downgrade_full_is_integrity_only_not_verified(tmp_path, capsys):
    data = _downgrade_full(SERVER.read_bytes())
    r = verify_evidence_zip(data)
    assert not r.any_failed
    assert r.summary["verdict"] == "INTEGRITY_ONLY"
    assert r.summary["sealed"] is None
    assert all("timestamp is unaffected" not in c.detail for c in r.checks)
    assert _cli(tmp_path, data) == 4
    out = capsys.readouterr().out
    assert "INTEGRITY ONLY — no qualified timestamp; the files are only consistent with manifest.json" in out
    assert "✓ VERIFIED" not in out
    assert _cli(tmp_path, data, "--quiet") == 4
    assert "INTEGRITY ONLY" in capsys.readouterr().err


def test_genuine_package_without_timestamp_is_integrity_only(tmp_path):
    r = verify_evidence_zip(NO_TSR.read_bytes())
    assert _check(r, "eidas_signature").skipped
    assert r.summary["verdict"] == "INTEGRITY_ONLY"
    assert _check(r, "sealed_identity").skipped
    assert _cli(tmp_path, NO_TSR.read_bytes()) == 4


@pytest.mark.parametrize("fx", SAAS_ZIPS, ids=lambda p: p.name)
def test_genuine_timestamped_packages_still_verify(fx, tmp_path):
    r = verify_evidence_zip(fx.read_bytes())
    assert r.summary["verdict"] == "VERIFIED", [(c.name, c.detail) for c in r.checks if c.status == "fail"]
    assert _check(r, "sealed_identity").passed
    assert _check(r, "unlisted_files").passed
    assert _cli(tmp_path, fx.read_bytes()) == 0


def test_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    assert "4  INTEGRITY ONLY" in out and "0  VERIFIED" in out and "1  FAILED" in out


# ─── 01-D2: proof.json vs the sealed payload ────────────────────────────────

@pytest.mark.parametrize("field,value", [
    ("source_url", "https://example.org/other"),
    ("final_url", "https://example.org/other"),
    ("captured_at", "2026-10-20T08:00:00Z"),
    ("proof_id", "00000000-0000-0000-0000-000000000000"),
])
def test_proof_json_identity_mismatch_fails(field, value):
    r = verify_evidence_zip(_edit_proof(SERVER.read_bytes(), lambda p: p.__setitem__(field, value)))
    c = _check(r, "sealed_identity")
    assert not c.passed and not c.skipped
    assert any(p["field"] == field and p["file"] == "proof.json" for p in c.extra["problems"])
    assert r.summary["verdict"] == "FAILED"


def test_manifest_proof_id_mismatch_fails():
    files = _files(SERVER.read_bytes())
    man = json.loads(files["manifest.json"])
    man["proof_id"] = "00000000-0000-0000-0000-000000000000"
    files["manifest.json"] = json.dumps(man).encode()
    r = verify_evidence_zip(_write(files))
    c = _check(r, "sealed_identity")
    assert any(p["file"] == "manifest.json" and p["field"] == "proof_id" for p in c.extra["problems"])
    assert r.summary["verdict"] == "FAILED"


def test_proof_json_artifact_hash_differs_from_payload():
    def edit(p):
        p["mhtml_sha256"] = "0" * 64
    data = _edit_proof(SERVER.read_bytes(), edit)
    payload = json.loads(_files(data)["timestamp/eidas_payload.json"])
    r = verify_evidence_zip(data)
    if payload.get("mhtml_sha256"):
        assert any(p["field"] == "mhtml_sha256" for p in _check(r, "sealed_identity").extra["problems"])
    assert r.summary["verdict"] == "FAILED"


def test_captured_at_normalised_like_the_server():
    sealed = json.loads(_files(SERVER.read_bytes())["timestamp/eidas_payload.json"])["captured_at"]
    variant = sealed.replace("Z", ".000+00:00")
    assert _norm_time(variant) == _norm_time(sealed)
    r = verify_evidence_zip(_edit_proof(SERVER.read_bytes(), lambda p: p.__setitem__("captured_at", variant)))
    assert r.summary["verdict"] == "VERIFIED", _check(r, "sealed_identity").detail


@pytest.mark.parametrize("mode,source", [("browser", "browser_extension"), ("browser", None),
                                         (None, "browser_extension"), ("file_digest", None)])
def test_server_capture_relabelled_fails(mode, source):
    def edit(p):
        if mode is not None:
            p["capture"]["mode"] = mode
        if source is not None:
            p["capture"]["source"] = source
    r = verify_evidence_zip(_edit_proof(SERVER.read_bytes(), edit))
    assert r.summary["verdict"] == "FAILED"
    c = _check(r, "sealed_identity")
    assert any(p["field"].startswith("capture.") for p in c.extra.get("problems", [])), c.detail


def test_file_digest_relabelled_as_server_fails():
    def edit(p):
        p["capture"]["mode"] = "server"
        p["capture"]["source"] = "server_url"
    r = verify_evidence_zip(_edit_proof(FILE_DIGEST.read_bytes(), edit))
    assert r.summary["verdict"] == "FAILED"
    assert any(p["field"] == "capture.mode" and p["sealed"] == "file_digest"
               for p in _check(r, "sealed_identity").extra["problems"])


def test_capture_mode_removed_from_proof_json_still_verifies():
    def edit(p):
        p["capture"].pop("mode", None)
        p["capture"].pop("source", None)
    r = verify_evidence_zip(_edit_proof(SERVER.read_bytes(), edit))
    assert r.summary["verdict"] == "VERIFIED"
    assert r.summary["sealed"]["capture_mode"] == "server"


def test_embedded_capture_meta_must_equal_file():
    def edit(p):
        p["capture"]["meta"] = dict(p["capture"]["meta"], capture_engine="browser_extension")
    r = verify_evidence_zip(_edit_proof(SERVER.read_bytes(), edit))
    assert not _check(r, "cross_references").passed
    assert r.summary["verdict"] == "FAILED"


def test_sealed_capture_mode_rules():
    assert sealed_capture_mode({"mode": "file_digest", "capture_engine": "playwright"}) == "file_digest"
    assert sealed_capture_mode({"capture_engine": "browser_extension"}) == "browser"
    assert sealed_capture_mode({"capture_engine": "playwright", "extension_version": "1.9.0"}) == "browser"
    assert sealed_capture_mode({"capture_engine": "playwright",
                                "capture_visibility": "authenticated_visible"}) == "browser"
    assert sealed_capture_mode({"capture_engine": "playwright"}) == "server"
    assert sealed_capture_mode({"capture_engine": "other"}) is None
    assert sealed_capture_mode(None) is None
    # a browser capture relabelled as a server capture (adv/ext/mode_srv)
    probs = _capture_mode_problems("browser", {"capture": {"mode": "server", "source": "server_url"}})
    assert {p["field"] for p in probs} == {"capture.mode", "capture.source"}
    assert not _capture_mode_problems("browser", {"capture": {"mode": "browser", "source": "browser_extension"}})
    assert not _capture_mode_problems("server", {"capture": {"mode": "server", "source": "monitor"}})


def test_network_derivative_edit_fails():
    files = _files(SERVER.read_bytes())
    if "network/dns.json" not in files:
        pytest.skip("fixture has no network/dns.json")
    dns = json.loads(files["network/dns.json"])
    dns["forged"] = True
    files["network/dns.json"] = json.dumps(dns, indent=2).encode()
    r = verify_evidence_zip(_write(files))
    assert r.summary["verdict"] == "FAILED"
    assert any(p["file"] == "network/dns.json" for p in _check(r, "sealed_identity").extra["problems"])


# ─── 3 / 5: sealed facts and the unsealed files are stated ─────────────────

def test_sealed_facts_in_summary_json_and_human_output(tmp_path, capsys):
    data = SERVER.read_bytes()
    payload = json.loads(_files(data)["timestamp/eidas_payload.json"])
    r = verify_evidence_zip(data)
    s = r.summary["sealed"]
    for k in ("proof_id", "source_url", "final_url", "captured_at"):
        assert s[k] == payload[k]
    assert s["capture_mode"] == "server" and s["timestamp_gen_time"]
    assert "screenshot.png" in s["sealed_files"] and "timestamp/eidas_payload.json" in s["sealed_files"]
    ns = r.summary["not_sealed"]
    assert {"report.pdf", "proof.json", "manifest.json"} <= set(ns["generated_at_download"])
    assert ns["timestamp_helpers"]
    assert not set(ns["generated_at_download"]) & set(s["sealed_files"])

    assert _cli(tmp_path, data, "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["sealed"]["source_url"] == payload["source_url"]
    assert out["summary"]["verdict"] == "VERIFIED"

    assert _cli(tmp_path, data) == 0
    txt = capsys.readouterr().out
    assert "Sealed facts" in txt
    assert payload["source_url"] in txt and payload["captured_at"] in txt and payload["proof_id"] in txt
    assert "Capture mode:   server" in txt
    assert "NOT sealed (generated at download time): README.md, manifest.json, proof.json, report.pdf" in txt


def test_browser_capture_note_is_printed(tmp_path, capsys, monkeypatch):
    import gpa_verify.core as core
    monkeypatch.setattr(core, "sealed_capture_mode", lambda cm: "browser")
    data = _edit_proof(SERVER.read_bytes(), lambda p: p["capture"].update(mode="browser",
                                                                          source="browser_extension"))
    r = verify_evidence_zip(data)
    assert r.summary["verdict"] == "VERIFIED"
    assert r.summary["sealed"]["capture_note"] == BROWSER_CAPTURE_NOTE
    _cli(tmp_path, data)
    assert "supplied by the customer's own browser" in capsys.readouterr().out


# ─── 01-D6: files not listed in manifest.json ───────────────────────────────

def test_extra_file_not_in_manifest_fails(tmp_path):
    files = _files(SERVER.read_bytes())
    files["evidence_note.txt"] = b"Additional statement\n"
    data = _write(files, recompute_manifest=False)
    r = verify_evidence_zip(data)
    c = _check(r, "unlisted_files")
    assert not c.passed and c.extra["extras"] == ["evidence_note.txt"]
    assert r.summary["verdict"] == "FAILED"
    assert _cli(tmp_path, data) == 1


def test_os_metadata_is_only_reported():
    files = _files(SERVER.read_bytes())
    files[".DS_Store"] = b"\x00"
    files["__MACOSX/._screenshot.png"] = b"\x00"
    r = verify_evidence_zip(_write(files, recompute_manifest=False))
    c = _check(r, "unlisted_files")
    assert c.passed and "operating-system metadata" in c.detail
    assert r.summary["verdict"] == "VERIFIED"


def test_unlisted_rule_matches_server_junk_definition():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("manifest.json", json.dumps({"files": {"a.txt": {}}}))
        z.writestr("a.txt", b"a")
        z.writestr("__MACOSX/notes.txt", b"x")   # not OS junk: only __MACOSX/._*
    c = check_unlisted_files(zipfile.ZipFile(out), {"files": {"a.txt": {}}})
    assert not c.passed and c.extra["extras"] == ["__MACOSX/notes.txt"]


# ─── 01 N16: anchor_witness is INFO, not PASS ───────────────────────────────

def test_witness_is_info_and_not_counted(tmp_path, capsys):
    r = verify_evidence_zip(SERVER.read_bytes())
    w = _check(r, "anchor_witness")
    if w.skipped:
        pytest.skip("fixture witness skipped")
    assert w.status == "info" and not w.counts_as_pass
    assert r.summary["checks_passed"] == sum(1 for c in r.checks if c.status == "pass")
    assert r.summary["checks_info"] == 1
    assert r.to_dict()["checks"][[c.name for c in r.checks].index("anchor_witness")]["status"] == "info"
    _cli(tmp_path, SERVER.read_bytes())
    out = capsys.readouterr().out
    assert "[INFO]  anchor_witness" in out and ", 1 info)" in out


# ─── 01-D10: SaaS report.pdf ────────────────────────────────────────────────

def _report_pdf(src=SERVER) -> bytes:
    return _files(src.read_bytes())["report.pdf"]


def test_saas_report_detected_and_explained(tmp_path, capsys):
    pdf = _report_pdf()
    assert detect_kind(pdf) == "saas_report"
    kind, r = verify_bytes(pdf)
    assert kind == "saas_report" and r.summary["verdict"] == "NOT_VERIFIABLE"
    assert r.proof_id == json.loads(_files(SERVER.read_bytes())["manifest.json"])["proof_id"]
    assert not any(c.name == "input_format" for c in r.checks)
    assert _cli(tmp_path, pdf, name="report.pdf") == 3
    out = capsys.readouterr().out
    assert "This is the unsealed human-readable report of a SaaS proof — verify its Evidence ZIP instead" in out


def test_saas_report_with_original_match(tmp_path, capsys):
    pdf = _report_pdf()
    zp = tmp_path / "pkg.zip"
    zp.write_bytes(SERVER.read_bytes())
    _, r = verify_bytes(pdf, original=SERVER.read_bytes())
    b = _check(r, "report_binding")
    assert b.passed and "MATCH" in b.detail
    assert r.summary["verdict"] == "NOT_VERIFIABLE" and r.summary["package_verdict"] == "VERIFIED"
    assert _cli(tmp_path, pdf, "--original", str(zp), name="report.pdf") == 3
    out = capsys.readouterr().out
    assert "MATCH" in out and "✓ VERIFIED" not in out


def test_saas_report_with_original_no_match(tmp_path, capsys):
    pdf = _report_pdf() + b"\n% edited\n"
    zp = tmp_path / "pkg.zip"
    zp.write_bytes(SERVER.read_bytes())
    _, r = verify_bytes(pdf, original=SERVER.read_bytes())
    b = _check(r, "report_binding")
    assert not b.passed and "NO MATCH" in b.detail
    assert r.summary["verdict"] == "FAILED"
    assert _cli(tmp_path, pdf, "--original", str(zp), name="report.pdf") == 1
    # report of another proof
    _, r2 = verify_bytes(_report_pdf(FILE_DIGEST), original=SERVER.read_bytes())
    assert not _check(r2, "report_binding").passed


# ─── Forensic Browser behaviour unchanged ───────────────────────────────────

def test_forensic_browser_zip_unchanged(tmp_path):
    r = verify_evidence_zip(FB_ZIP.read_bytes())
    assert r.summary["verdict"] == "VERIFIED"
    assert "sealed" not in r.summary and "not_sealed" not in r.summary
    assert not any(c.name in ("unlisted_files", "sealed_identity") for c in r.checks)
    assert _cli(tmp_path, FB_ZIP.read_bytes()) == 0
