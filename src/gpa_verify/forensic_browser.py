"""
gpa_verify.forensic_browser — verification of GetProofAnchor Forensic
Browser (desktop app) outputs.

Three output kinds are supported (formats are documented in
docs/forensic-browser-formats.md):

  1. ZIP package   (manifest.format = "getproofanchor-lite-N")
     RFC 3161 token over timestamp/eidas_payload.json, which lists the
     SHA-256 of every *sealed* file of the package.
  2. Sealed PDF    (PAdES document time-stamp, /SubFilter /ETSI.RFC3161)
     The qualified time-stamp covers the whole file, including every
     embedded artefact (/EmbeddedFiles) and the embedded manifest.json.
  3. Plain copy    ("…_bez-pecete.pdf", unsealed, for systems that strip
     PAdES seals). Carries a QR code + text block identifying the sealed
     original by SHA-256, session id and time-stamp serial. Not verifiable
     by itself; can be matched against the sealed original.

Every function here is a pure function of its inputs (bytes in, report
out) and performs no network access.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .core import CheckResult, VerifyReport
from . import pdfmini as P
from .tsp_verify import pem_to_der_list, token_checks, verify_token

FB_FORMATS = frozenset({"getproofanchor-lite-2"})
PLAIN_COPY_TYPE = "getproofanchor-plain-copy"

VERDICT_VERIFIED = "VERIFIED"
VERDICT_FAILED = "FAILED"
VERDICT_NOT_VERIFIABLE = "NOT_VERIFIABLE"


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _json(b: Optional[bytes]) -> Optional[Dict[str, Any]]:
    if b is None:
        return None
    try:
        o = json.loads(b.decode("utf-8"))
    except Exception:
        return None
    return o if isinstance(o, dict) else None


def _finish(report: VerifyReport, verdict: Optional[str] = None,
            notes: Optional[List[str]] = None, **extra: Any) -> VerifyReport:
    checks = report.checks
    any_failed = any(not c.passed and not c.skipped for c in checks)
    if verdict is None:
        verdict = VERDICT_VERIFIED if (not any_failed and any(c.passed for c in checks)) else VERDICT_FAILED
    if any_failed:
        verdict = VERDICT_FAILED
    q = qualified_status(checks)
    if q is not None:
        notes = list(notes or [])
        root = next((c.extra.get("trust_root") for c in checks
                     if c.name.endswith("tsa_trust_root") and c.passed), None)
        if q == "not_checked":
            notes.insert(0, "Qualified (eIDAS) status NOT checked: the time-stamp is a valid "
                            "RFC 3161 time-stamp from a TSA chaining to "
                            f"{root or 'the TSA root'}; supply an EU Trusted List with --tsl "
                            "to check qualified status.")
        elif q == "per_supplied_tsl":
            notes.insert(0, "Qualified status taken from the supplied Trusted List, whose own "
                            "XML signature is not verified by this tool.")
    report.summary = {
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.passed),
        "checks_failed": sum(1 for c in checks if not c.passed and not c.skipped),
        "checks_skipped": sum(1 for c in checks if c.skipped),
        "verdict": verdict,
        **({"qualified": q} if q is not None else {}),
        **({"notes": notes} if notes else {}),
        **extra,
    }
    return report


def qualified_status(checks) -> Optional[str]:
    """'per_supplied_tsl' | 'not_checked' | 'failed' | None (no time-stamp).
    Review S1: never call a time-stamp qualified unless a Trusted List said so."""
    tq = [c for c in checks if c.name.endswith("tsl_qualified")]
    tok = [c for c in checks if c.name.endswith("timestamp_token") or c.name == "eidas_signature"]
    if not tq or not any(not c.skipped for c in tok):
        return None   # no time-stamp token at all (review round 2, N1)
    if any(not c.passed and not c.skipped for c in tq):
        return "failed"
    if all(c.passed and not c.skipped for c in tq):
        return "per_supplied_tsl"
    return "not_checked"


def _parse_time(s: Any) -> Optional[datetime]:
    if not isinstance(s, str) or not s.strip():
        return None
    t = s.strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
    if re.match(r"^\d{4}-\d{2}-\d{2} \d", t):
        t = t.replace(" ", "T", 1)
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Trusted-List / certificate inputs supplied by the user (--tsl, --certs)
# ─────────────────────────────────────────────────────────────────────────────

def load_trust_inputs(paths: List[str], cert_paths: List[str] = ()) -> Tuple[List[Tuple[str, bytes]], List[bytes]]:
    """Load Trusted List XML files and extra certificates from paths.

    A --tsl path may be: a TSL .xml file, a directory of .xml files, or a
    Forensic Browser / SaaS ZIP (its timestamp/tsl/*.xml and
    timestamp/tsa_certs.pem are used)."""
    import os
    tsl: List[Tuple[str, bytes]] = []
    certs: List[bytes] = []
    for p in paths or []:
        if os.path.isdir(p):
            for n in sorted(os.listdir(p)):
                if n.lower().endswith(".xml"):
                    with open(os.path.join(p, n), "rb") as f:
                        tsl.append((n, f.read()))
            continue
        with open(p, "rb") as f:
            raw = f.read()
        if raw[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                for n in z.namelist():
                    low = n.lower()
                    if low.startswith("timestamp/tsl/") and low.endswith(".xml"):
                        tsl.append((f"{os.path.basename(p)}:{n}", z.read(n)))
                    elif low in ("timestamp/tsa_certs.pem", "timestamp/tsa_signer_cert.pem"):
                        certs.extend(pem_to_der_list(z.read(n)))
        else:
            tsl.append((os.path.basename(p), raw))
    for p in cert_paths or []:
        with open(p, "rb") as f:
            raw = f.read()
        ders = pem_to_der_list(raw)
        certs.extend(ders if ders else [raw])
    return tsl, certs


# ═════════════════════════════════════════════════════════════════════════════
# 1. ZIP package
# ═════════════════════════════════════════════════════════════════════════════

def is_fb_manifest(manifest: Optional[Dict[str, Any]], proof: Optional[Dict[str, Any]] = None) -> bool:
    fmt = (manifest or {}).get("format") or ""
    if isinstance(fmt, str) and fmt.startswith("getproofanchor-lite-"):
        return True
    app = (proof or {}).get("app_version") or ""
    return isinstance(app, str) and app.startswith("gpa-forensic-browser")


def verify_fb_zip(zip_bytes: bytes) -> VerifyReport:
    report = VerifyReport()
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile as exc:
        report.checks.append(CheckResult("zip_open", False, detail=f"not a valid ZIP: {exc}"))
        return _finish(report)

    from .core import MAX_ZIP_ENTRY, zip_structure_problems
    zprobs = zip_structure_problems(zf)
    if zprobs:
        report.checks.append(CheckResult("zip_structure", False, detail="; ".join(zprobs[:5])))
        return _finish(report)

    names = [n for n in zf.namelist() if not n.endswith("/")]
    corrupt: Dict[str, str] = {}

    def read(n: str) -> Optional[bytes]:
        try:
            if zf.getinfo(n).file_size > MAX_ZIP_ENTRY:
                corrupt[n] = "member exceeds the size limit"
                return None
            return zf.read(n)
        except KeyError:
            return None
        except Exception as exc:  # bad CRC, truncated/corrupt deflate data, …
            corrupt[n] = f"{type(exc).__name__}: {exc}"
            return None

    manifest = _json(read("manifest.json"))
    proof = _json(read("proof.json"))
    payload_raw = read("timestamp/eidas_payload.json")
    payload = _json(payload_raw)
    tsr = read("timestamp/eidas.tsr")
    capture_meta = _json(read("capture/capture_meta.json"))

    report.bundle_format = f"forensic-browser-zip ({(manifest or {}).get('format', '?')})"
    report.proof_id = (manifest or {}).get("session_id") or (proof or {}).get("session_id")
    report.generated_at = (manifest or {}).get("generated_at")

    # ── fb_package ────────────────────────────────────────────────────────
    probs: List[str] = []
    if manifest is None:
        probs.append("manifest.json missing or invalid")
    if proof is None:
        probs.append("proof.json missing or invalid")
    if payload is None:
        probs.append("timestamp/eidas_payload.json missing or invalid")
    if tsr is None:
        probs.append("timestamp/eidas.tsr missing")
    fmt = (manifest or {}).get("format")
    if manifest is not None and fmt not in FB_FORMATS:
        probs.append(f"unsupported Forensic Browser format {fmt!r} (supported: {sorted(FB_FORMATS)})")
    sids = {
        "manifest.json": (manifest or {}).get("session_id"),
        "proof.json": (proof or {}).get("session_id"),
        "eidas_payload.json": (payload or {}).get("session_id"),
        "capture_meta.json": (capture_meta or {}).get("session_id"),
    }
    present = {k: v for k, v in sids.items() if v is not None}
    if len(set(present.values())) > 1:
        probs.append(f"session_id differs between files: {present}")
    for k in ("format",):
        if payload is not None and manifest is not None and payload.get(k) != manifest.get(k):
            probs.append(f"eidas_payload.{k} != manifest.{k}")
    report.checks.append(CheckResult(
        "fb_package", not probs,
        detail=("; ".join(probs) if probs else
                f"Forensic Browser package {fmt}, session {report.proof_id}, "
                f"app {(proof or {}).get('app_version')}"),
        extra={"session_ids": sids, "app_version": (proof or {}).get("app_version")},
    ))
    if manifest is None:
        return _finish(report)

    # ── bundle_integrity: every file against manifest ─────────────────────
    files_meta = manifest.get("files") or {}
    mism: List[Dict[str, Any]] = []
    missing: List[str] = []
    ok = 0
    for path, meta in files_meta.items():
        if not isinstance(meta, dict) or not meta.get("sha256"):
            mism.append({"file": path, "error": "manifest entry has no sha256"})
            continue
        data = read(path)
        if data is None:
            missing.append(path)
            continue
        act = _sha256(data)
        if act != meta["sha256"]:
            mism.append({"file": path, "expected_sha256": meta["sha256"], "actual_sha256": act,
                         "sealed": bool(meta.get("sealed"))})
        elif isinstance(meta.get("size"), int) and meta["size"] != len(data):
            mism.append({"file": path, "expected_size": meta["size"], "actual_size": len(data)})
        else:
            ok += 1
    extras = sorted(n for n in names if n not in files_meta and n != "manifest.json"
                    and not n.startswith("__MACOSX/") and not n.endswith(".DS_Store"))
    integ = manifest.get("integrity") or {}
    count_probs = []
    sealed_n = sum(1 for m in files_meta.values() if isinstance(m, dict) and m.get("sealed"))
    if isinstance(integ.get("sealed_count"), int) and integ["sealed_count"] != sealed_n:
        count_probs.append(f"integrity.sealed_count={integ['sealed_count']} but {sealed_n} files marked sealed")
    if isinstance(integ.get("unsealed_count"), int) and integ["unsealed_count"] != len(files_meta) - sealed_n:
        count_probs.append("integrity.unsealed_count inconsistent")
    if payload_raw is not None and manifest.get("payload_sha256") and manifest["payload_sha256"] != _sha256(payload_raw):
        count_probs.append("manifest.payload_sha256 != SHA-256(timestamp/eidas_payload.json)")
    passed = not mism and not missing and not extras and not count_probs and not corrupt
    parts = [f"{ok}/{len(files_meta)} files match manifest"]
    if corrupt:
        parts.append(f"{len(corrupt)} corrupt ZIP entr(y/ies): {sorted(corrupt)[:3]}")
    if missing:
        parts.append(f"{len(missing)} missing")
    if mism:
        parts.append(f"{len(mism)} mismatched")
    if extras:
        parts.append(f"{len(extras)} file(s) not declared in manifest")
    parts += count_probs
    report.checks.append(CheckResult(
        "bundle_integrity", passed, detail=", ".join(parts),
        extra={"missing": missing, "mismatches": mism[:20], "undeclared_files": extras[:20],
               "note": "manifest.json itself is not covered by the timestamp; the "
                       "binding of sealed files is checked by sealed_binding"},
    ))

    # ── sealed_binding: eidas_payload.json (what the TSA signed) ──────────
    fails: List[Dict[str, Any]] = []
    bound = 0
    pfiles = (payload or {}).get("files") if payload else None
    if not isinstance(pfiles, dict) or not pfiles:
        fails.append({"error": "eidas_payload.json has no 'files' map"})
        pfiles = {}
    for path, sha in pfiles.items():
        data = read(path)
        if data is None:
            fails.append({"file": path, "error": "sealed file missing from package"})
            continue
        act = _sha256(data)
        if act != sha:
            fails.append({"file": path, "sealed_sha256": sha, "actual_sha256": act,
                          "error": "content differs from the time-stamped hash"})
        else:
            bound += 1
        m = files_meta.get(path)
        if not isinstance(m, dict) or not m.get("sealed"):
            fails.append({"file": path, "error": "sealed in payload but not marked sealed in manifest"})
    for path, m in files_meta.items():
        if isinstance(m, dict) and m.get("sealed") and path not in pfiles:
            fails.append({"file": path, "error": "manifest claims sealed=true but file is NOT in the time-stamped payload"})
    # payload metadata must agree with proof.json
    if payload and proof:
        pairs = [("finished_at", proof.get("finished_at")),
                 ("operator_username", (proof.get("operator") or {}).get("username"))]
        for k, v in pairs:
            if k in payload and payload.get(k) != v:
                fails.append({"field": k, "payload": payload.get(k), "proof": v,
                              "error": "time-stamped payload disagrees with proof.json"})
    # sidecars
    for side, target in (("timestamp/eidas_payload.sha256", "timestamp/eidas_payload.json"),
                         ("capture/capture_meta.sha256", "capture/capture_meta.json")):
        s = read(side)
        t = read(target)
        if s is not None and t is not None:
            decl = (s.decode("utf-8", "replace").split() or [""])[0].lower()
            if decl != _sha256(t):
                fails.append({"file": side, "declared": decl, "actual": _sha256(t),
                              "error": "sidecar hash does not match"})
    unsealed = sorted(p for p, m in files_meta.items() if isinstance(m, dict) and not m.get("sealed"))
    report.checks.append(CheckResult(
        "sealed_binding", not fails,
        detail=(f"{bound}/{len(pfiles)} files bound to the time-stamped payload "
                f"(SHA-256 {(_sha256(payload_raw) if payload_raw else '?')[:16]}…)"
                if not fails else f"{len(fails)} binding problem(s)"),
        extra={"sealed_files": sorted(pfiles), "unsealed_files": unsealed,
               **({"failures": fails[:20]} if fails else {})},
    ))

    # ── pages: per-page artefacts (multi-page sessions) ───────────────────
    report.checks.append(_check_pages(proof, capture_meta, read, names, pfiles))

    # ── timestamp_token / tsa_chain / tsl_qualified ───────────────────────
    pool: List[bytes] = []
    for n in ("timestamp/tsa_certs.pem", "timestamp/tsa_signer_cert.pem"):
        b = read(n)
        if b:
            pool.extend(pem_to_der_list(b))
    tsl_files = [(n, read(n) or b"") for n in names
                 if n.lower().startswith("timestamp/tsl/") and n.lower().endswith(".xml")]
    info = None
    if tsr is not None and payload_raw is not None:
        info = verify_token(tsr, payload_raw, extra_cert_ders=pool)
        report.checks.extend(token_checks(
            info, pool_ders=pool, tsl_files=tsl_files,
            tsl_missing_detail="no Trusted List bundled (timestamp/tsl/*.xml absent)"))
    else:
        report.checks.append(CheckResult("timestamp_token", False, detail="token or payload missing"))

    # ── timestamp_metadata: producer's unsealed claims vs the token ───────
    if info is not None:
        report.checks.append(_check_ts_metadata(info, read, payload_raw, tsl_files))

    # ── report_pdf: human-readable report (unsealed) ──────────────────────
    rp = read("report.pdf")
    if rp is not None:
        report.checks.append(_check_report_pdf(rp, report.proof_id, info, payload_raw))

    notes = [
        "Files marked sealed=true are bound to the RFC 3161 time-stamp through "
        "timestamp/eidas_payload.json; a VERIFIED verdict proves they existed in "
        "this exact form at genTime.",
        "Unsealed files (report.pdf, token, certificates, Trusted List snapshot, "
        "verification summaries) were created after the time-stamp; they are only "
        "protected by manifest.json, which is itself not time-stamped.",
    ]
    return _finish(report, notes=notes,
                   timestamp=info.summary() if info is not None else None)


def _check_pages(proof, capture_meta, read, names, pfiles) -> CheckResult:
    if not proof:
        return CheckResult("pages", False, detail="proof.json missing")
    pages = proof.get("pages") or []
    fails: List[Dict[str, Any]] = []
    if not isinstance(pages, list) or not pages:
        return CheckResult("pages", False, detail="proof.json lists no pages")
    pc = proof.get("page_count")
    if isinstance(pc, int) and pc != len(pages):
        fails.append({"error": f"page_count={pc} but {len(pages)} pages listed"})
    if capture_meta and isinstance(capture_meta.get("page_count"), int) and capture_meta["page_count"] != len(pages):
        fails.append({"error": "capture_meta.page_count disagrees with proof.json"})
    cm_raw = read("capture/capture_meta.json")
    if proof.get("capture_meta_sha256") and cm_raw is not None and _sha256(cm_raw) != proof["capture_meta_sha256"]:
        fails.append({"error": "proof.capture_meta_sha256 != SHA-256(capture/capture_meta.json)"})
    fieldmap = (("screenshot_sha256", "screenshot.png"), ("page_html_sha256", "page.html"),
                ("mhtml_sha256", "page.mhtml"))
    seen_dirs = set()
    checked = 0
    for pg in pages:
        idx = pg.get("index")
        if not isinstance(idx, int):
            fails.append({"error": "page without integer index"})
            continue
        d = f"pages/{idx:02d}/"
        seen_dirs.add(d)
        for fld, fn in fieldmap:
            want = pg.get(fld)
            if not want:
                continue
            data = read(d + fn)
            if data is None:
                fails.append({"page": idx, "file": d + fn, "error": "declared in proof.json but missing"})
                continue
            if _sha256(data) != want:
                fails.append({"page": idx, "file": d + fn, "expected": want, "actual": _sha256(data)})
            elif (d + fn) not in pfiles:
                fails.append({"page": idx, "file": d + fn, "error": "not in time-stamped payload"})
            else:
                checked += 1
    for n in names:
        m = re.match(r"pages/(\d+)/", n)
        if m and f"pages/{m.group(1)}/" not in seen_dirs:
            fails.append({"file": n, "error": "page directory not listed in proof.json"})
    if proof.get("include_video") and not any(n.startswith("media/") for n in pfiles):
        fails.append({"error": "proof.include_video=true but no sealed media/ file"})
    return CheckResult(
        "pages", not fails,
        detail=(f"{len(pages)} page(s), {checked} per-page artefact hash(es) consistent with proof.json "
                "and sealed" if not fails else f"{len(fails)} page problem(s)"),
        extra={"pages": [{"index": p.get("index"), "url": p.get("url"), "captured_at": p.get("captured_at")}
                         for p in pages if isinstance(p, dict)],
               **({"failures": fails[:20]} if fails else {})},
    )


def _check_ts_metadata(info, read, payload_raw, tsl_files) -> CheckResult:
    probs: List[str] = []
    meta = _json(read("timestamp/eidas_meta.json")) or {}
    s = info.summary()
    if meta:
        if meta.get("serial") is not None and str(meta.get("serial")) != s["serial"]:
            probs.append(f"eidas_meta.serial {meta.get('serial')} != token serial {s['serial']}")
        mt, tt = _parse_time(meta.get("gen_time")), info.gen_time
        if mt and tt and mt != tt:
            probs.append(f"eidas_meta.gen_time {meta.get('gen_time')} != token genTime {s['gen_time']}")
        if meta.get("policy_oid") and meta.get("policy_oid") != info.policy:
            probs.append("eidas_meta.policy_oid != token policy")
        if payload_raw is not None and meta.get("payload_sha256") and meta["payload_sha256"] != _sha256(payload_raw):
            probs.append("eidas_meta.payload_sha256 != SHA-256(eidas_payload.json)")
    vr = _json(read("timestamp/eidas_verification_report.json")) or {}
    if vr:
        if vr.get("serial_number") is not None and str(vr["serial_number"]) != s["serial"]:
            probs.append("eidas_verification_report.serial_number != token serial")
        if vr.get("imprint_digest_hex") and vr["imprint_digest_hex"].lower() != (info.imprint_hex or ""):
            probs.append("eidas_verification_report.imprint_digest_hex != token imprint")
    qc = _json(read("timestamp/qualified_context.json")) or {}
    tl = qc.get("trusted_list") or {}
    if tl.get("bundled_file"):
        raw = read(tl["bundled_file"])
        if raw is None:
            probs.append(f"qualified_context names {tl['bundled_file']} but it is missing")
        elif tl.get("tsl_sha256") and tl["tsl_sha256"] != _sha256(raw):
            probs.append("qualified_context.trusted_list.tsl_sha256 != SHA-256 of bundled Trusted List")
    return CheckResult(
        "timestamp_metadata", not probs,
        detail=("eidas_meta / verification summary / qualified_context agree with the token"
                if not probs else "; ".join(probs)),
        extra={"tsl_status_at_capture": tl.get("status"), "tsl_url": tl.get("tsl_url"),
               "lotl_sha256": tl.get("lotl_sha256"),
               "note": "these producer-written files are not time-stamped; only their "
                       "consistency with the token is checked"},
    )


def _check_report_pdf(rp: bytes, sid: Optional[str], info, payload_raw) -> CheckResult:
    try:
        doc = P.PDFDocument(rp)
        text = "\n".join(P.extract_text(doc))
    except Exception as exc:
        return CheckResult("report_pdf", False, detail=f"report.pdf unreadable: {exc}")
    probs = []
    if sid and sid not in text:
        probs.append("session id not found in report text")
    if info is not None and info.serial is not None and str(info.serial) not in text:
        probs.append("time-stamp serial not found in report text")
    if payload_raw is not None and _sha256(payload_raw) not in text:
        probs.append("payload SHA-256 not found in report text")
    return CheckResult(
        "report_pdf", not probs,
        detail=("human-readable report cites this session, payload hash and time-stamp serial "
                "(report.pdf itself is NOT sealed)" if not probs else "; ".join(probs)),
    )


# ═════════════════════════════════════════════════════════════════════════════
# 2. PAdES sealed PDF
# ═════════════════════════════════════════════════════════════════════════════

_BR_RE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


class _Sig:
    def __init__(self, num: Optional[int], obj: Dict[str, Any], dict_off: int):
        self.num = num
        self.obj = obj
        self.dict_off = dict_off
        br = obj.get("ByteRange")
        self.byterange = br if isinstance(br, list) else None
        self.subfilter = str(obj.get("SubFilter") or "")
        self.type = str(obj.get("Type") or "")
        self.in_acroform = False
        self.field_name: Optional[str] = None

    @property
    def end(self) -> int:
        b = self.byterange
        return b[2] + b[3] if b and len(b) == 4 else -1

    @property
    def is_doc_ts(self) -> bool:
        return self.subfilter == "ETSI.RFC3161" or self.type == "DocTimeStamp"


MAX_SIGNATURE_DICTS = 64
_OBJ_HEAD_RE = re.compile(rb"(?<![0-9])(\d+)\s+(\d+)\s+obj\b")


class TooManySignatures(Exception):
    pass


def _find_signatures(doc: P.PDFDocument) -> List[_Sig]:
    import bisect

    data = doc.data
    sigs: Dict[int, _Sig] = {}
    # one linear pass over object headers, then bisect per /ByteRange (review R3)
    heads = [m.start() for m in _OBJ_HEAD_RE.finditer(data)]
    seen_heads = set()
    for k, m in enumerate(_BR_RE.finditer(data)):
        if k >= MAX_SIGNATURE_DICTS * 4:
            raise TooManySignatures(f"more than {MAX_SIGNATURE_DICTS * 4} /ByteRange entries")
        i = bisect.bisect_left(heads, m.start()) - 1
        if i < 0:
            continue
        off = heads[i]
        if off in seen_heads:
            continue
        seen_heads.add(off)
        try:
            num, gen, obj = P.Parser(data, resolver=doc).parse_indirect_at(off)
        except P.PDFError:
            continue
        if isinstance(obj, dict) and "ByteRange" in obj and "Contents" in obj and off not in sigs:
            sigs[off] = _Sig(num, obj, off)
            if len(sigs) > MAX_SIGNATURE_DICTS:
                raise TooManySignatures(f"more than {MAX_SIGNATURE_DICTS} signature dictionaries")
    # mark AcroForm membership
    try:
        af = doc.resolve(doc.root.get("AcroForm")) or {}
        stack = list(doc.resolve(af.get("Fields")) or [])
        seen = set()
        while stack:
            fr = stack.pop()
            if isinstance(fr, P.Ref):
                if fr in seen:
                    continue
                seen.add(fr)
            f = doc.resolve(fr)
            if not isinstance(f, dict):
                continue
            stack.extend(doc.resolve(f.get("Kids")) or [])
            v = f.get("V")
            if isinstance(v, P.Ref):
                off = doc.object_offset(v.num)
                if off in sigs:
                    sigs[off].in_acroform = True
                    t = doc.resolve(f.get("T"))
                    sigs[off].field_name = t.text() if isinstance(t, P.PDFString) else None
    except Exception:
        pass
    return sorted(sigs.values(), key=lambda s: s.end)


def _check_byterange(doc: P.PDFDocument, sig: _Sig) -> Tuple[List[str], Optional[bytes], int]:
    """Returns (problems, token_der, padding_len)."""
    data = doc.data
    probs: List[str] = []
    br = sig.byterange
    if not br or len(br) != 4 or not all(isinstance(x, int) and x >= 0 for x in br):
        return ["ByteRange is not four non-negative integers"], None, 0
    a, l1, b, l2 = br
    if a != 0:
        probs.append("ByteRange does not start at byte 0")
    if l1 > b:
        probs.append("ByteRange segments overlap")
    if b + l2 > len(data):
        probs.append(f"ByteRange extends past end of file ({b + l2} > {len(data)})")
        return probs, None, 0
    gap = data[l1:b]
    if not (gap[:1] == b"<" and gap[-1:] == b">" and re.fullmatch(rb"[0-9A-Fa-f]*", gap[1:-1])):
        probs.append("the excluded gap is not exactly the hex-encoded /Contents string")
        return probs, None, 0
    # the gap must belong to THIS signature dictionary
    if not (sig.dict_off < l1 < b):
        probs.append("excluded gap is not inside this signature dictionary")
    raw = bytes.fromhex(gap[1:-1].decode())
    from asn1crypto import cms
    try:
        ci = cms.ContentInfo.load(raw, strict=False)
        n = len(ci.dump())
    except Exception:
        # asn1crypto load ignores trailing data only in non-strict mode; find DER length
        n = _der_len(raw)
    tok = raw[:n]
    pad = raw[n:]
    if pad.strip(b"\x00"):
        probs.append("non-zero bytes in /Contents padding after the token (Contents altered)")
    return probs, tok, len(pad)


def _der_len(b: bytes) -> int:
    if len(b) < 2:
        return len(b)
    ln = b[1]
    if ln < 0x80:
        return 2 + ln
    k = ln & 0x7F
    return 2 + k + int.from_bytes(b[2:2 + k], "big")


def _same(a: Any, b: Any, depth: int = 0) -> bool:
    """Semantic equality of parsed PDF objects (stream offsets ignored)."""
    if depth > P.MAX_NESTING:
        return False
    if isinstance(a, P.Stream) or isinstance(b, P.Stream):
        return (isinstance(a, P.Stream) and isinstance(b, P.Stream) and a.raw == b.raw
                and _same(a.dict, b.dict, depth + 1))
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k], depth + 1) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y, depth + 1) for x, y in zip(a, b))
    return a == b


def _analyze_post_seal(doc: P.PDFDocument, sealed_end: int, sigs: List[_Sig]) -> Tuple[bool, str, Dict[str, Any]]:
    """Classify everything after the sealed byte range.

    Allowed after a document time-stamp (PAdES-LTV, ETSI EN 319 142-1 §5.4):
    a Document Security Store (/DSS, /VRI, certificate / CRL / OCSP streams)
    and further document time-stamps. Anything else is a modification.

    Method (review round 2): the sealed revision is parsed on its own from
    the sealed bytes; then EVERY object of the final document (as a viewer
    resolves it through the final xref, object streams included) is compared
    with the sealed one. Each difference must match a permitted LTV pattern.
    """
    data = doc.data
    tail = data[sealed_end:]
    if not tail:
        return True, "signed byte range covers the entire file — no changes after sealing", {"revisions_after": 0}
    if not tail.strip(b" \t\r\n\x00"):
        return True, (f"{len(tail)} trailing whitespace byte(s) outside the signed range, "
                      "no PDF content after sealing"), {"revisions_after": 0, "trailing_bytes": len(tail)}

    later = sorted((s for s in doc.sections if s.offset >= sealed_end), key=lambda s: s.offset)
    if not later:
        return False, (f"{len(tail)} byte(s) appended after sealing that are not a valid "
                       "incremental update"), {"appended_bytes": len(tail)}

    try:
        sealed = P.PDFDocument(data[:sealed_end])
    except P.PDFError as exc:
        return False, f"sealed revision cannot be parsed on its own: {exc}", {}
    if any("rebuilt" in w for w in sealed.warnings) or not sealed.sections or sealed.sections[0].offset < 0:
        return False, "sealed revision's cross-reference table cannot be read", {}
    sealed_xref = sealed.sections[0].offset
    if sealed_xref not in {s.offset for s in doc.sections}:
        return False, ("MODIFIED AFTER SEALING: the cross-reference chain of the final document "
                       "does not pass through the sealed revision"), {}
    if doc.trailer.get("Root") != sealed.trailer.get("Root"):
        return False, "MODIFIED AFTER SEALING: document catalog (/Root) replaced", {}

    disallowed: List[Dict[str, Any]] = []
    changes: List[Dict[str, Any]] = []

    # objects written after sealing but not listed in any later xref (shadow objects)
    listed = {s.offset for s in later}
    for sec in later:
        listed.update(e[1] for e in sec.entries.values() if e[0] == "n")
    for m in _OBJ_HEAD_RE.finditer(data, sealed_end):
        if m.start() not in listed:
            disallowed.append({"object": int(m.group(1)), "offset": m.start(),
                               "classified": "object body not listed in any cross-reference section"})
            if len(disallowed) > 50:
                break

    for sec in later:
        if sec.duplicates:
            disallowed.append({"object": sec.duplicates[0], "revision_xref": sec.offset,
                               "classified": "object number listed twice in one xref section"})

    dss_struct, dss_streams, dss_problems = _collect_dss(doc, doc.root.get("DSS"))
    # LTV renewal (e.g. pyHanko ltaupdate) re-points VRI keys at new
    # dictionaries; the superseded DSS objects of earlier post-seal revisions
    # stay in the file unreferenced. Accept them if they were DSS structure in
    # their own revision and are unchanged since (review round 3, B1).
    for sec in later[:-1] if len(later) > 1 else []:
        if sec.end <= 0 or len(later) > 32:
            continue
        try:
            rdoc = P.PDFDocument(data[:sec.end])
        except P.PDFError:
            continue
        r_struct, r_streams, r_probs = _collect_dss(rdoc, rdoc.root.get("DSS"))
        if r_probs:
            continue
        for n in r_struct:
            if n not in dss_struct and _same(_safe_get(rdoc, n), _safe_get(doc, n)):
                dss_struct.add(n)
        for n in r_streams:
            if n not in dss_streams and _same(_safe_get(rdoc, n), _safe_get(doc, n)):
                dss_streams.add(n)
    later_sig_nums = {s.num for s in sigs if s.end > sealed_end and s.num is not None}
    xref_stream_offsets = {s.offset for s in later if s.kind == "stream"}
    root_num = doc.trailer["Root"].num if isinstance(doc.trailer.get("Root"), P.Ref) else None
    info_num = doc.trailer.get("Info").num if isinstance(doc.trailer.get("Info"), P.Ref) else None
    if doc.trailer.get("Info") != sealed.trailer.get("Info"):
        info_num = None   # a replaced Info object is classified like any other new object

    ctx = _Ctx(doc, sealed, dss_struct, dss_streams, later_sig_nums, root_num, info_num,
               xref_stream_offsets)
    # appearance streams of new, invisible time-stamp widgets
    for num in sorted(set(doc.xref) - set(sealed.xref)):
        o = _safe_get(doc, num)
        if _is_ts_widget_obj(o, later_sig_nums) and _widget_ok(o)[0]:
            ap = o.get("AP")
            ap = doc.resolve(ap) if isinstance(ap, P.Ref) else ap
            if isinstance(ap, dict):
                for v in ap.values():
                    if isinstance(v, P.Ref):
                        ctx.widget_ap.add(v.num)

    nums = sorted(set(doc.xref) | set(sealed.xref))
    if len(nums) > 1_000_000:
        return False, "too many objects", {}
    for num in nums:
        if num == 0:
            continue
        cur_e, old_e = doc.xref.get(num), sealed.xref.get(num)
        cur = _safe_get(doc, num) if cur_e and cur_e[0] != "f" else None
        old = _safe_get(sealed, num) if old_e and old_e[0] != "f" else None
        if cur is _BROKEN or old is _BROKEN:
            disallowed.append({"object": num, "classified": "unparsable object"})
            continue
        if old is None and cur is None:
            continue
        if cur is None:
            disallowed.append({"object": num, "classified": "deleted after sealing"})
            continue
        if cur_e and old_e and cur_e[0] == "n" and old_e[0] == "n" and cur_e[2] != old_e[2]:
            disallowed.append({"object": num, "classified": "generation number changed"})
            continue
        if old is not None and _same(old, cur):
            continue
        ok, why = _classify_change(ctx, num, cur, old)
        rec = {"object": num, "new": old is None, "classified": why}
        changes.append(rec)
        if not ok:
            disallowed.append(rec)

    # duplicate dictionary keys in post-seal objects: viewers disagree on
    # which value wins, so the comparison above cannot be trusted for them
    for in_file, where, key in doc.duplicate_keys:
        if (in_file and where >= sealed_end) or (not in_file and where not in sealed.xref):
            disallowed.append({"object": None, "classified": f"duplicate dictionary key /{key} after sealing"})
            break

    extra = {"revisions_after": len(later), "changed_objects": changes[:50]}
    if dss_problems and dss_struct:
        disallowed.append({"object": None, "classified": "invalid DSS: " + "; ".join(dss_problems[:3])})
    if disallowed:
        return False, (f"MODIFIED AFTER SEALING: {len(disallowed)} object change(s) in "
                       f"{len(later)} later revision(s) are not LTV/time-stamp updates "
                       f"(e.g. {disallowed[0]})"), {**extra, "disallowed": disallowed[:50]}
    kinds = sorted({c["classified"] for c in changes})
    tail_after = data[max(s.end for s in later):]
    if tail_after.strip(b" \t\r\n\x00"):
        return False, f"{len(tail_after)} byte(s) of unrecognised data after the last revision", extra
    return True, (f"{len(later)} later revision(s) contain only permitted LTV / document "
                  f"time-stamp updates ({', '.join(kinds) or 'no object changes'})"), extra


_BROKEN = object()


def _safe_get(d: P.PDFDocument, num: int) -> Any:
    try:
        return d.get_object(num)
    except P.PDFError:
        return _BROKEN


class _Ctx:
    def __init__(self, doc, sealed, dss_struct, dss_streams, later_sig_nums, root_num,
                 info_num, xref_stream_offsets):
        self.doc, self.sealed = doc, sealed
        self.dss_struct, self.dss_streams = dss_struct, dss_streams
        self.later_sig_nums = later_sig_nums
        self.root_num, self.info_num = root_num, info_num
        self.xref_stream_offsets = xref_stream_offsets
        self.widget_ap: set = set()


_DSS_KEYS = {"Type", "Certs", "CRLs", "OCSPs", "VRI"}
_VRI_ENTRY_KEYS = {"Type", "Cert", "CRL", "OCSP", "TU", "TS"}


def _collect_dss(doc, dss_ref) -> Tuple[set, set, List[str]]:
    """Return (structural object numbers, data stream numbers, problems) of the
    DSS. Structure: DSS dict → Certs/CRLs/OCSPs arrays of stream refs, VRI dict
    → per-signature dicts with Cert/CRL/OCSP arrays of stream refs and TS
    stream. Anything else is reported as a problem."""
    struct: set = set()
    streams: set = set()
    probs: List[str] = []
    if dss_ref is None:
        return struct, streams, probs

    def take(x, what):
        if isinstance(x, P.Ref):
            struct.add(x.num)
            return doc.get_object(x.num)
        return x

    def stream_ref(x, where):
        if not isinstance(x, P.Ref):
            probs.append(f"{where}: entry is not an indirect stream")
            return
        o = doc.get_object(x.num)
        if not isinstance(o, P.Stream) or o.get("Type") in ("XObject", "ObjStm", "XRef", "Metadata"):
            probs.append(f"{where}: object {x.num} is not a certificate/CRL/OCSP stream")
            return
        streams.add(x.num)

    def stream_array(x, where):
        arr = take(x, where)
        if not isinstance(arr, list):
            probs.append(f"{where} is not an array")
            return
        if len(arr) > 10000:
            probs.append(f"{where} too long")
            return
        for e in arr:
            stream_ref(e, where)

    dss = take(dss_ref, "DSS")
    if not isinstance(dss, dict):
        return struct, streams, ["/DSS is not a dictionary"]
    if set(dss) - _DSS_KEYS:
        probs.append("DSS has unexpected keys " + ",".join(sorted(set(dss) - _DSS_KEYS)))
    for k in ("Certs", "CRLs", "OCSPs"):
        if k in dss:
            stream_array(dss[k], f"DSS/{k}")
    if "VRI" in dss:
        vri = take(dss["VRI"], "VRI")
        if not isinstance(vri, dict) or len(vri) > 10000:
            probs.append("DSS/VRI is not a dictionary")
        else:
            for key, ent in vri.items():
                if key == "Type":
                    continue
                d = take(ent, "VRI entry")
                if not isinstance(d, dict):
                    probs.append("VRI entry is not a dictionary")
                    continue
                if set(d) - _VRI_ENTRY_KEYS:
                    probs.append("VRI entry has unexpected keys " + ",".join(sorted(set(d) - _VRI_ENTRY_KEYS)))
                for k in ("Cert", "CRL", "OCSP"):
                    if k in d:
                        stream_array(d[k], f"VRI/{k}")
                if "TS" in d:
                    stream_ref(d["TS"], "VRI/TS")
    return struct, streams, probs


def _zero_rect(r) -> bool:
    return (isinstance(r, list) and len(r) == 4 and all(isinstance(v, (int, float)) for v in r)
            and (r[2] - r[0]) == 0 and (r[3] - r[1]) == 0)


_WIDGET_KEYS = {"Type", "Subtype", "FT", "V", "T", "TU", "F", "Ff", "Rect", "P", "AP", "MK",
                "DA", "Border", "StructParent"}


def _widget_ok(o: Dict[str, Any]) -> Tuple[bool, str]:
    extra_keys = set(o) - _WIDGET_KEYS
    if extra_keys:
        return False, "time-stamp widget with unexpected keys " + ",".join(sorted(extra_keys))
    if o.get("Subtype") not in (None, "Widget"):
        return False, "time-stamp field is not a widget"
    if "Rect" in o and not _zero_rect(o.get("Rect")):
        return False, "visible time-stamp widget"
    return True, "time-stamp field (invisible)"


def _classify_change(ctx: "_Ctx", num: int, obj: Any, old: Any) -> Tuple[bool, str]:
    """Rules: a sealed object may change only in the few ways an LTV /
    document time-stamp writer needs; a new object is allowed only as DSS
    structure/data, the revision's own xref stream, an object stream, or a new
    document time-stamp (signature dict + invisible widget + its appearance)."""
    doc, sealed = ctx.doc, ctx.sealed
    is_new = old is None
    if isinstance(obj, P.Stream) or isinstance(old, P.Stream):
        if not is_new:
            return False, "sealed stream rewritten"   # whatever its /Type (review round 2)
        t = obj.get("Type")
        ent = doc.xref.get(num)
        if t == "XRef":
            if ent and ent[0] == "n" and ent[1] in ctx.xref_stream_offsets:
                return True, "xref stream"
            return False, "stream typed /XRef that is not a cross-reference section"
        if t == "ObjStm":
            return True, "object stream (its objects are checked one by one)"
        if num in ctx.dss_streams:
            return True, "DSS data (certificate/CRL/OCSP)"
        if num in ctx.widget_ap and t == "XObject" and obj.get("Subtype") == "Form" \
                and len(obj.raw) <= 65536:
            return True, "time-stamp widget appearance"
        return False, "new content stream"
    t = obj.get("Type") if isinstance(obj, dict) else None

    if num in ctx.dss_struct:
        if is_new:
            return True, "DSS / VRI"
        sroot = sealed.root
        was_dss = (isinstance(old, dict) and old.get("Type") == "DSS") or (
            isinstance(sroot.get("DSS"), P.Ref) and sroot["DSS"].num == num)
        return (True, "DSS updated") if was_dss else (False, "sealed object reused as DSS structure")

    if not isinstance(obj, dict):
        return False, "non-dictionary object changed" if not is_new else "new non-dictionary object"

    if t == "DocTimeStamp" or num in ctx.later_sig_nums:
        if not is_new:
            return False, "sealed object turned into a signature dictionary"
        keys_ok = set(obj) <= {"Type", "Filter", "SubFilter", "Contents", "ByteRange", "M",
                               "Name", "Reason", "Location", "ContactInfo", "Prop_Build"}
        if obj.get("SubFilter") == "ETSI.RFC3161" and keys_ok:
            return True, "document time-stamp"
        return False, "new signature (not a plain document time-stamp)"
    if is_new and _is_ts_widget_obj(obj, ctx.later_sig_nums):
        return _widget_ok(obj)

    if not isinstance(old, dict):
        return False, "new object of unknown purpose" if is_new else "changed object"
    diff = {k for k in set(old) | set(obj) if not _same(old.get(k), obj.get(k))}
    if not diff:
        return True, "rewritten (identical)"
    if num == ctx.root_num:
        bad = diff - {"DSS", "AcroForm", "Extensions", "Version"}
        if "Version" in diff and not _version_bump_ok(old.get("Version"), obj.get("Version")):
            bad.add("Version")
        if bad:
            return False, "catalog changed: " + ",".join(sorted(bad))
        if "AcroForm" in diff:
            o_af, n_af = old.get("AcroForm"), obj.get("AcroForm")
            if isinstance(o_af, P.Ref) or isinstance(n_af, P.Ref):
                return False, "catalog AcroForm reference replaced"
            ok, why = _acroform_ok(ctx, o_af, n_af)
            if not ok:
                return False, "catalog AcroForm: " + why
        if "Extensions" in diff and not _extensions_ok(obj.get("Extensions")):
            return False, "catalog /Extensions is not a developer-extensions dictionary"
        return True, "catalog: " + ",".join(sorted(diff))
    if num == ctx.info_num:
        bad = diff - {"Producer", "ModDate"}
        return (not bad, "document info (Producer/ModDate)" if not bad else "document info changed: " + ",".join(sorted(bad)))
    if t == "Page" or "Annots" in diff:
        if diff == {"Annots"}:
            old_a = _ref_nums(sealed, old.get("Annots"))
            new_a = _ref_nums(doc, obj.get("Annots"))
            if not isinstance(old.get("Annots"), P.Ref) and not isinstance(obj.get("Annots"), P.Ref) \
                    and old_a is not None and new_a is not None and old_a <= new_a and \
                    all(_is_ts_widget(doc, n, ctx.later_sig_nums) for n in new_a - old_a):
                return True, "page: time-stamp widget added"
        return False, "page changed: " + ",".join(sorted(diff))
    if t == "AcroForm" or "Fields" in diff:
        ok, why = _acroform_ok(ctx, old, obj)
        return (True, "AcroForm fields (time-stamp)") if ok else (False, "AcroForm changed: " + why)
    return False, "changed object: " + ",".join(sorted(diff))


def _version_bump_ok(old: Any, new: Any) -> bool:
    """Catalog /Version may only be raised (LTV writers set 1.7+)."""
    try:
        o = tuple(int(x) for x in str(old).split(".")) if old is not None else (1, 0)
        n = tuple(int(x) for x in str(new).split("."))
    except (TypeError, ValueError):
        return False
    return isinstance(new, P.Name) and n >= o and n <= (2, 0)


def _extensions_ok(x: Any) -> bool:
    if not isinstance(x, dict):
        return False
    for v in x.values():
        if not isinstance(v, dict) or set(v) - {"Type", "BaseVersion", "ExtensionLevel", "URL"}:
            return False
    return True


def _ref_nums(doc, x) -> Optional[set]:
    x = doc.resolve(x) if isinstance(x, P.Ref) else x
    if x is None:
        return set()
    if not isinstance(x, list):
        return None
    return {r.num for r in x if isinstance(r, P.Ref)}


def _acroform_ok(ctx: "_Ctx", old, new) -> Tuple[bool, str]:
    if not isinstance(new, dict):
        return False, "not a dictionary"
    if not isinstance(old, dict):
        old = {}
    diff = {k for k in set(old) | set(new) if not _same(old.get(k), new.get(k))}
    if diff - {"Fields", "SigFlags"}:
        return False, ",".join(sorted(diff - {"Fields", "SigFlags"}))
    if isinstance(old.get("Fields"), P.Ref) or isinstance(new.get("Fields"), P.Ref):
        if "Fields" in diff:
            return False, "indirect /Fields array replaced"
    of, nf = _ref_nums(ctx.sealed, old.get("Fields")), _ref_nums(ctx.doc, new.get("Fields"))
    if of is None or nf is None or not of <= nf:
        return False, "existing fields removed or replaced"
    if not all(_is_ts_widget(ctx.doc, n, ctx.later_sig_nums) for n in nf - of):
        return False, "added field is not a document time-stamp"
    return True, "fields appended"


def _is_ts_widget_obj(o, later_sig_nums) -> bool:
    return isinstance(o, dict) and o.get("FT") == "Sig" and isinstance(o.get("V"), P.Ref) \
        and o["V"].num in later_sig_nums


def _is_ts_widget(doc, n, later_sig_nums) -> bool:
    return _is_ts_widget_obj(doc.get_object(n), later_sig_nums)


def _name_text(x: Any) -> Optional[str]:
    if isinstance(x, P.PDFString):
        return x.text()
    if isinstance(x, str):
        return re.sub(r"#([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), str(x))
    return None


def list_attachments(doc: P.PDFDocument, sealed_end: Optional[int] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(name: Optional[str], fs_ref: Any, source: str) -> None:
        fs = doc.resolve(fs_ref)
        if not isinstance(fs, dict):
            return
        ef = doc.resolve(fs.get("EF")) or {}
        sref = ef.get("UF") or ef.get("F") if isinstance(ef, dict) else None
        stm = doc.resolve(sref)
        if not isinstance(stm, P.Stream):
            return
        key = sref.num if isinstance(sref, P.Ref) else id(stm)
        if key in seen:
            return
        seen.add(key)
        try:
            content = P.decode_stream(stm, doc)
            err = None
        except P.PDFError as exc:
            content, err = b"", str(exc)
        rec: Dict[str, Any] = {
            "name": name or _name_text(fs.get("UF")) or _name_text(fs.get("F")),
            "filename": _name_text(fs.get("UF")) or _name_text(fs.get("F")),
            "description": _name_text(doc.resolve(fs.get("Desc"))),
            "mime": _name_text(stm.get("Subtype")),
            "relationship": _name_text(fs.get("AFRelationship")),
            "size": len(content),
            "sha256": _sha256(content) if err is None else None,
            "source": source,
        }
        params = doc.resolve(stm.get("Params"))
        if isinstance(params, dict):
            if isinstance(params.get("Size"), int):
                rec["declared_size"] = params["Size"]
            ck = doc.resolve(params.get("CheckSum"))
            if isinstance(ck, P.PDFString):
                rec["declared_md5"] = bytes(ck).hex()
                rec["md5_ok"] = hashlib.md5(content).digest() == bytes(ck)
        if err:
            rec["error"] = err
        if sealed_end is not None and stm.offset >= 0:
            rec["within_sealed_range"] = stm.offset + len(stm.raw) <= sealed_end
        rec["_data"] = content
        out.append(rec)

    names = doc.resolve(doc.root.get("Names"))
    if isinstance(names, dict) and names.get("EmbeddedFiles") is not None:
        for k, v in doc.name_tree(names["EmbeddedFiles"]):
            add(k, v, "EmbeddedFiles")
    for v in doc.resolve(doc.root.get("AF")) or []:
        add(None, v, "AF")
    for i, pg in enumerate(doc.pages(), 1):
        for a in doc.resolve(pg.get("Annots")) or []:
            ao = doc.resolve(a)
            if isinstance(ao, dict) and ao.get("Subtype") == "FileAttachment":
                add(None, ao.get("FS"), f"annotation p.{i}")
    return out


def _match_attachment(path: str, atts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    flat = path.replace("/", "_")
    for a in atts:
        d = a.get("description") or ""
        if d == path or d.startswith(path + " "):
            return a
    for a in atts:
        if a.get("name") == flat or a.get("filename") == flat or a.get("name") == path:
            return a
    for a in atts:
        n = a.get("name") or ""
        if n.startswith(flat + "."):
            return a
    return None


def verify_sealed_pdf(pdf_bytes: bytes, *, tsl_files: Optional[List[Tuple[str, bytes]]] = None,
                      extra_certs: Optional[List[bytes]] = None,
                      _doc: Optional[P.PDFDocument] = None) -> VerifyReport:
    report = VerifyReport()
    report.bundle_format = "pades-document-timestamp"
    tsl_files = tsl_files or []
    extra_certs = extra_certs or []
    try:
        doc = _doc or P.PDFDocument(pdf_bytes)
    except P.PDFError as exc:
        report.checks.append(CheckResult("pdf_structure", False, detail=f"cannot parse PDF: {exc}"))
        return _finish(report)
    revs = doc.revisions()
    report.checks.append(CheckResult(
        "pdf_structure", not doc.encrypted,
        detail=(f"PDF {doc.version}"
                + (f" (catalog /Version {doc.root.get('Version')})" if doc.root.get("Version") else "")
                + f", {len(revs)} revision(s), {len(doc.pages())} page(s)"
                + (", xref warnings: " + "; ".join(doc.warnings) if doc.warnings else "")
                if not doc.encrypted else "encrypted PDF — not supported"),
        extra={"revisions": [{"start": r.start, "end": r.end,
                              "xref": r.xref.kind if r.xref else None} for r in revs],
               "warnings": doc.warnings},
    ))
    try:
        sigs = _find_signatures(doc)
    except TooManySignatures as exc:
        report.checks.append(CheckResult("pades_signature", False, detail=f"refused: {exc}"))
        return _finish(report)
    if not sigs:
        report.checks.append(CheckResult("pades_signature", False, detail="no signature dictionary with /ByteRange found"))
        return _finish(report)

    eof_ends = set(doc.eof_ends())
    primary_info = None
    primary: Optional[_Sig] = None
    sig_summ = []
    for i, sig in enumerate(sigs):
        pre = "" if i == 0 else f"ts{i + 1}."
        probs, tok, padlen = _check_byterange(doc, sig)
        if sig.end not in eof_ends and sig.end != len(doc.data):
            probs.append("signed range does not end at a revision boundary (%%EOF)")
        sig_summ.append({"object": sig.num, "type": sig.type, "subfilter": sig.subfilter,
                         "byterange": sig.byterange, "field": sig.field_name,
                         "in_acroform": sig.in_acroform, "contents_padding_bytes": padlen})
        cover = (f"ByteRange {sig.byterange} covers {sig.byterange[1] + sig.byterange[3] if sig.byterange else '?'} "
                 f"of {len(doc.data)} bytes (all except the /Contents value)")
        if not sig.in_acroform:
            probs.append("signature dictionary is not referenced by any AcroForm field")
        if not sig.is_doc_ts:
            report.checks.append(CheckResult(
                f"{pre}pades_signature", False, skipped=True,
                detail=f"signature with SubFilter {sig.subfilter or '?'} — only document "
                       "time-stamps (ETSI.RFC3161) are verified by this tool"))
            continue
        report.checks.append(CheckResult(
            f"{pre}pades_signature", not probs,
            detail=("; ".join(probs) if probs else
                    f"/DocTimeStamp /ETSI.RFC3161 (field {sig.field_name!r}); {cover}"),
            extra=sig_summ[-1],
        ))
        if tok is None:
            continue
        br = sig.byterange
        signed = doc.data[br[0]:br[0] + br[1]] + doc.data[br[2]:br[2] + br[3]]
        info = verify_token(tok, signed, extra_cert_ders=extra_certs)
        report.checks.extend(token_checks(
            info, pool_ders=extra_certs, tsl_files=tsl_files, name_prefix=pre,
            tsl_missing_detail=("qualified status not checked offline — the PDF embeds no "
                                "Trusted List; re-run with --tsl <EU TSL .xml | directory | "
                                "Forensic Browser ZIP>")))
        if primary is None:
            primary, primary_info = sig, info

    if primary is None:
        return _finish(report)

    try:
        ok, detail, extra = _analyze_post_seal(doc, primary.end, sigs)
    except Exception as exc:
        ok, detail, extra = False, f"cannot analyse data after sealing: {type(exc).__name__}: {exc}", {}
    if primary.end < len(doc.data):
        extra["sealed_revision"] = {"bytes": primary.end,
                                    "sha256": _sha256(doc.data[:primary.end])}
        if not ok:
            detail += (f" — the sealed version is the first {primary.end} bytes of this file "
                       f"(SHA-256 {extra['sealed_revision']['sha256'][:16]}…)")
    report.checks.append(CheckResult("post_seal_changes", ok, detail=detail, extra=extra))

    try:
        return _verify_sealed_tail(doc, report, primary, primary_info, sigs, sig_summ, tsl_files)
    except Exception as exc:  # malformed objects must never crash the verifier
        report.checks.append(CheckResult(
            "pdf_objects", False, detail=f"document structure unreadable: {type(exc).__name__}: {exc}"))
        return _finish(report, timestamp=primary_info.summary() if primary_info else None)


def _verify_sealed_tail(doc, report, primary, primary_info, sigs, sig_summ, tsl_files) -> VerifyReport:
    # ── attachments ──
    atts = list_attachments(doc, primary.end)
    manifest_att = next((a for a in atts if (a.get("name") or "").lower() == "manifest.json"), None)
    manifest = _json(manifest_att["_data"]) if manifest_att else None
    fails: List[Dict[str, Any]] = []
    unsealed = [a["name"] for a in atts if a.get("within_sealed_range") is False]
    for a in atts:
        if "declared_size" in a and a["declared_size"] != a["size"]:
            fails.append({"attachment": a["name"], "error": "Params/Size mismatch"})
        if a.get("md5_ok") is False:
            fails.append({"attachment": a["name"], "error": "Params/CheckSum (MD5) mismatch"})
        if a.get("error"):
            fails.append({"attachment": a["name"], "error": a["error"]})
    if unsealed:
        fails.append({"error": "attachment(s) stored outside the time-stamped byte range", "attachments": unsealed})
    matched = 0
    if manifest is not None:
        mfiles = manifest.get("files") or {}
        used = {id(manifest_att)}
        for path, meta in mfiles.items():
            a = _match_attachment(path, atts)
            if a is None:
                fails.append({"file": path, "error": "listed in embedded manifest.json but not attached"})
                continue
            used.add(id(a))
            if not isinstance(meta, dict) or meta.get("sha256") != a["sha256"]:
                fails.append({"file": path, "attachment": a["name"], "manifest_sha256": (meta or {}).get("sha256"),
                              "actual_sha256": a["sha256"]})
            elif isinstance(meta.get("size"), int) and meta["size"] != a["size"]:
                fails.append({"file": path, "error": "size mismatch"})
            else:
                matched += 1
            a["manifest_path"] = path
        for a in atts:
            if id(a) not in used:
                fails.append({"attachment": a["name"], "error": "attachment not listed in embedded manifest.json"})
    att_list = [{k: v for k, v in a.items() if not k.startswith("_")} for a in atts]
    if atts:
        report.checks.append(CheckResult(
            "attachments", not fails,
            detail=(f"{len(atts)} embedded file(s), all inside the sealed range"
                    + (f"; {matched}/{len(manifest.get('files') or {})} match embedded manifest.json"
                       if manifest is not None else "; no embedded manifest.json to compare")
                    if not fails else f"{len(fails)} attachment problem(s)"),
            extra={"attachments": att_list, **({"failures": fails[:30]} if fails else {})},
        ))
    else:
        report.checks.append(CheckResult("attachments", False, skipped=True, detail="no embedded files"))

    # ── Forensic Browser evidence consistency ──
    proof_att = next((a for a in atts if (a.get("name") or "") == "proof.json"), None)
    proof = _json(proof_att["_data"]) if proof_att else None
    text_pages = P.extract_text(doc)
    text = "\n".join(text_pages)
    is_fb = is_fb_manifest(manifest, proof)
    if is_fb:
        report.bundle_format = f"forensic-browser-pades ({(manifest or {}).get('format', '?')})"
        report.proof_id = (proof or {}).get("session_id") or (manifest or {}).get("session_id")
        report.generated_at = (manifest or {}).get("generated_at")
        report.checks.append(_check_pdf_evidence(proof, manifest, atts, text, report.proof_id))
    else:
        m = re.search(r"sess-\d+", text)
        report.proof_id = m.group(0) if m else None

    notes = [
        "The document time-stamp covers every byte of the PDF except its own "
        "/Contents value — including all embedded artefacts — so a VERIFIED verdict proves "
        "the document and its attachments existed in this exact form at genTime.",
    ]
    return _finish(report, notes=notes,
                   timestamp=primary_info.summary() if primary_info else None,
                   signatures=sig_summ,
                   attachments=[{k: a.get(k) for k in ("name", "manifest_path", "size", "sha256",
                                                       "within_sealed_range")} for a in atts])


def _check_pdf_evidence(proof, manifest, atts, text, sid) -> CheckResult:
    fails: List[Dict[str, Any]] = []
    by_path = {a.get("manifest_path"): a for a in atts if a.get("manifest_path")}
    if proof is None:
        return CheckResult("evidence_consistency", False, detail="proof.json not attached")
    if manifest and manifest.get("session_id") and manifest.get("session_id") != proof.get("session_id"):
        fails.append({"error": "manifest.session_id != proof.session_id"})
    cm = by_path.get("capture/capture_meta.json")
    if cm is not None:
        if proof.get("capture_meta_sha256") and proof["capture_meta_sha256"] != cm["sha256"]:
            fails.append({"error": "proof.capture_meta_sha256 != attached capture_meta.json"})
        cmj = _json(cm["_data"]) or {}
        if cmj.get("session_id") and cmj["session_id"] != proof.get("session_id"):
            fails.append({"error": "capture_meta.session_id != proof.session_id"})
    side = by_path.get("capture/capture_meta.sha256")
    if side is not None and cm is not None:
        decl = (side["_data"].decode("utf-8", "replace").split() or [""])[0].lower()
        if decl != cm["sha256"]:
            fails.append({"error": "capture_meta.sha256 sidecar mismatch"})
    pages = proof.get("pages") or []
    checked = 0
    for pg in pages:
        idx = pg.get("index")
        if not isinstance(idx, int):
            continue
        for fld, fn in (("screenshot_sha256", "screenshot.png"), ("page_html_sha256", "page.html"),
                        ("mhtml_sha256", "page.mhtml")):
            want = pg.get(fld)
            if not want:
                continue
            a = by_path.get(f"pages/{idx:02d}/{fn}")
            if a is None:
                fails.append({"page": idx, "file": fn, "error": "declared in proof.json but not attached"})
            elif a["sha256"] != want:
                fails.append({"page": idx, "file": fn, "proof": want, "attached": a["sha256"]})
            else:
                checked += 1
    if isinstance(proof.get("page_count"), int) and proof["page_count"] != len(pages):
        fails.append({"error": "proof.page_count disagrees with pages list"})
    # visible text: session id and the hashes it cites
    text_notes = []
    if sid and sid not in text:
        fails.append({"error": "session id not shown in the document text"})
    cited = set(re.findall(r"\b[0-9a-f]{64}\b", text))
    known = {a["sha256"] for a in atts if a.get("sha256")}
    unknown = sorted(cited - known)
    if unknown:
        fails.append({"error": "document text cites SHA-256 values that match no attachment",
                      "values": unknown[:10]})
    text_notes.append(f"{len(cited)} SHA-256 value(s) printed in the document all match attachments"
                      if not unknown else "")
    return CheckResult(
        "evidence_consistency", not fails,
        detail=(f"proof.json ↔ attachments consistent ({len(pages)} page(s), {checked} artefact hash(es)); "
                f"{len(cited)} SHA-256 value(s) printed in the document match attachments"
                if not fails else f"{len(fails)} inconsistency(ies)"),
        extra={"session_id": proof.get("session_id"), "app_version": proof.get("app_version"),
               "pages": [{"index": p.get("index"), "url": p.get("url"), "captured_at": p.get("captured_at")}
                         for p in pages if isinstance(p, dict)],
               **({"failures": fails[:20]} if fails else {})},
    )


# ═════════════════════════════════════════════════════════════════════════════
# 3. Unsealed plain copy ("bez pečetě") and unsealed package report
# ═════════════════════════════════════════════════════════════════════════════

def read_copy_identification(doc: P.PDFDocument) -> Dict[str, Any]:
    """Extract the identification of the sealed original from a plain copy.

    Sources: (1) the QR code (decoded with the built-in pure-Python reader),
    (2) the printed text block. Both are returned; ``id`` is the merged view
    (QR preferred)."""
    from .qrdecode import QRError, decode_image

    out: Dict[str, Any] = {"qr": None, "qr_error": None, "text": {}, "id": {}}
    for pg in doc.pages()[:2]:
        for im in P.iter_page_images(doc, pg, max_side=1200):
            if abs(im.width - im.height) > 0.1 * max(im.width, im.height):
                continue
            try:
                raw = decode_image(im.width, im.height, im.channels, im.pixels)
            except QRError as exc:
                out["qr_error"] = str(exc)
                continue
            try:
                j = json.loads(raw.decode("utf-8"))
            except Exception:
                out["qr_error"] = "QR content is not JSON"
                out["qr_raw"] = raw.decode("utf-8", "replace")[:500]
                continue
            if isinstance(j, dict):
                out["qr"] = j
                break
        if out["qr"]:
            break
    text = "\n".join(P.extract_text(doc))
    out["text_excerpt_chars"] = len(text)
    t: Dict[str, Any] = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    kv: List[Tuple[str, str]] = []
    for i, ln in enumerate(lines):
        if ln.endswith(":") and i + 1 < len(lines):
            kv.append((ln[:-1].strip().lower(), lines[i + 1]))
        elif ": " in ln:
            k, v = ln.split(": ", 1)
            kv.append((k.strip().lower(), v.strip()))

    def find(*keys: str) -> Optional[str]:
        for k, v in kv:
            if any(key in k for key in keys):
                return v
        return None

    t["sid"] = find("id relace", "session id", "session")
    t["f"] = find("soubor originálu", "original file")
    t["sha256"] = find("otisk originálu", "original sha", "sha-256 of the original", "original (sha")
    t["size"] = find("velikost originálu", "original size", "size of the original")
    t["ts_serial"] = find("sériové číslo razítka", "serial number", "time-stamp serial", "timestamp serial")
    t["ts_time"] = find("čas orazítkování", "time-stamped at", "timestamp time", "sealed at")
    t["qtsp"] = find("poskytovatel (qtsp)", "qtsp", "provider")
    if t.get("sha256"):
        m = re.search(r"[0-9a-fA-F]{64}", t["sha256"])
        t["sha256"] = m.group(0).lower() if m else None
    if t.get("size"):
        digits = re.sub(r"[^0-9]", "", t["size"])
        t["size"] = int(digits) if digits else None
    out["text"] = {k: v for k, v in t.items() if v is not None}
    q = out["qr"] or {}
    merged = {k: q.get(k) for k in ("sid", "f", "sha256", "ts_serial", "ts_time") if q.get(k) is not None}
    for k, v in out["text"].items():
        merged.setdefault(k, v)
    out["id"] = merged
    out["full_text"] = text
    return out


def classify_pdf(doc: P.PDFDocument) -> str:
    """'sealed' | 'plain_copy' | 'fb_report' | 'unsigned'."""
    if _BR_RE.search(doc.data):
        return "sealed"
    try:
        creator = _name_text(doc.info.get("Creator")) or ""
        ident = read_copy_identification(doc)
    except Exception:
        return "plain_copy" if PLAIN_COPY_TYPE.encode() in doc.data else "unsigned"
    if (ident.get("qr") or {}).get("t") == PLAIN_COPY_TYPE or (
            ident["text"].get("sha256") and ident["text"].get("f")):
        return "plain_copy"
    if "GetProofAnchor" in creator:
        return "fb_report"
    return "unsigned"


def verify_plain_copy(copy_bytes: bytes, *, original: Optional[bytes] = None,
                      original_name: Optional[str] = None,
                      tsl_files: Optional[List[Tuple[str, bytes]]] = None,
                      extra_certs: Optional[List[bytes]] = None) -> VerifyReport:
    report = VerifyReport()
    report.bundle_format = "forensic-browser-plain-copy (unsealed)"
    try:
        doc = P.PDFDocument(copy_bytes)
        ident = read_copy_identification(doc)
    except Exception as exc:
        report.checks.append(CheckResult("pdf_structure", False, detail=f"cannot parse PDF: {exc}"))
        return _finish(report)
    idd = ident["id"]
    report.proof_id = idd.get("sid")
    report.generated_at = None

    # identification check: QR and text must agree where both exist
    conflicts = []
    q, t = ident.get("qr") or {}, ident.get("text") or {}
    for k in ("sid", "f", "sha256", "ts_serial"):
        if q.get(k) is not None and t.get(k) is not None and str(q[k]).strip() != str(t[k]).strip():
            conflicts.append(f"{k}: QR={q[k]!r} text={t[k]!r}")
    if q.get("ts_time") and t.get("ts_time") and _parse_time(q["ts_time"]) != _parse_time(t["ts_time"]):
        conflicts.append(f"ts_time: QR={q['ts_time']!r} text={t['ts_time']!r}")
    have = bool(idd.get("sha256"))
    src = "QR code + printed text" if q and t else ("QR code" if q else ("printed text" if t else "none"))
    report.checks.append(CheckResult(
        "copy_identification", have and not conflicts,
        detail=(f"identifies sealed original {idd.get('f')!r} SHA-256 {idd.get('sha256', '?')[:16]}…, "
                f"session {idd.get('sid')}, time-stamp serial {idd.get('ts_serial')} (source: {src})"
                if have and not conflicts else
                ("; ".join(conflicts) if conflicts else "no identification of a sealed original found")),
        extra={"qr": q or None, "text": t or None, "qr_error": ident.get("qr_error")},
    ))
    report.checks.append(CheckResult(
        "copy_integrity", False, skipped=True,
        detail="unsealed copy — its own integrity is NOT verifiable (no seal); "
               "only the sealed original carries the qualified time-stamp"))

    if original is None:
        notes = [
            "This is an UNSEALED plain copy (e.g. for import into a case system that "
            "strips PAdES seals). It cannot prove anything about itself.",
            "To check it, obtain the sealed original named above and run: "
            "gpa-verify <copy.pdf> --original <sealed.pdf>.",
        ]
        return _finish(report, verdict=VERDICT_NOT_VERIFIABLE, notes=notes, identification=idd)

    # ── with the sealed original ──
    orig = verify_sealed_pdf(original, tsl_files=tsl_files, extra_certs=extra_certs)
    for c in orig.checks:
        report.checks.append(CheckResult(f"original.{c.name}", c.passed, c.skipped, c.detail, c.extra))
    ts = orig.summary.get("timestamp") or {}
    probs = []
    facts = {}
    osha = _sha256(original)
    facts["sha256"] = osha == idd.get("sha256")
    if not facts["sha256"]:
        probs.append(f"SHA-256 of supplied original {osha[:16]}… != {str(idd.get('sha256'))[:16]}… cited by the copy")
    if t.get("size") is not None:
        facts["size"] = t["size"] == len(original)
        if not facts["size"]:
            probs.append(f"original size {len(original)} B != {t['size']} B cited by the copy")
    if idd.get("sid") is not None:
        facts["session_id"] = idd["sid"] == orig.proof_id
        if not facts["session_id"]:
            probs.append(f"session id {idd['sid']} != original's {orig.proof_id}")
    if idd.get("ts_serial") is not None:
        facts["ts_serial"] = str(idd["ts_serial"]) == str(ts.get("serial"))
        if not facts["ts_serial"]:
            probs.append(f"time-stamp serial {idd['ts_serial']} != original's {ts.get('serial')}")
    if idd.get("ts_time") is not None:
        ct, ot = _parse_time(idd["ts_time"]), _parse_time(ts.get("gen_time"))
        facts["ts_time"] = bool(ct and ot and abs((ct - ot).total_seconds()) < 1)
        if not facts["ts_time"]:
            probs.append(f"time-stamp time {idd['ts_time']} != original genTime {ts.get('gen_time')}")
    if idd.get("f") and original_name:
        facts["filename"] = original_name.endswith(idd["f"])  # informational only
    report.checks.append(CheckResult(
        "copy_binding", not probs,
        detail=("copy's identification data matches the supplied sealed original "
                "(SHA-256, session, time-stamp serial and time)" if not probs else "; ".join(probs)),
        extra={"facts": facts, "original_sha256": osha},
    ))

    # content consistency: hashes and URLs printed on the copy must exist in the original
    oatts = orig.summary.get("attachments") or []
    known = {a.get("sha256") for a in oatts if a.get("sha256")}
    oproof = None
    try:
        for a in list_attachments(P.PDFDocument(original)):
            if a.get("name") == "proof.json":
                oproof = _json(a["_data"])
    except Exception:
        oproof = None
    for pg in (oproof or {}).get("pages") or []:
        for k in ("screenshot_sha256", "page_html_sha256", "mhtml_sha256"):
            if pg.get(k):
                known.add(pg[k])
    ctext = ident.get("full_text") or ""
    cited = set(re.findall(r"\b[0-9a-f]{64}\b", ctext)) - {idd.get("sha256")}
    unknown = sorted(cited - known)
    urls_copy = set(re.findall(r"https?://\S+", ctext))
    urls_orig = {p.get("url") for p in (oproof or {}).get("pages") or []}
    url_unknown = sorted(u for u in urls_copy if u not in urls_orig)
    cprobs = []
    if unknown:
        cprobs.append(f"{len(unknown)} SHA-256 value(s) printed on the copy are not in the sealed original")
    if url_unknown:
        cprobs.append(f"URL(s) on the copy not captured in the original: {url_unknown[:3]}")
    report.checks.append(CheckResult(
        "copy_content_consistency", not cprobs,
        detail=(f"{len(cited)} artefact hash(es) and {len(urls_copy)} URL(s) printed on the copy "
                "are those sealed in the original" if not cprobs else "; ".join(cprobs)),
        extra={"unknown_hashes": unknown[:10], "unknown_urls": url_unknown[:10]},
    ))
    notes = [
        "PROVEN: the supplied original is a sealed, unmodified Forensic Browser document "
        "(see original.* checks) and it is exactly the file this copy identifies "
        "(SHA-256, session id, time-stamp serial and time).",
        "PROVEN: the hashes and URLs printed on the copy are those sealed in the original.",
        "NOT PROVEN: that the copy's pages, images and other text are a faithful rendering "
        "of the original — the copy is unsealed and its preview images are reduced. Rely "
        "on the sealed original for the evidence itself.",
    ]
    return _finish(report, notes=notes, identification=idd)


def verify_fb_report(pdf_bytes: bytes, *, original: Optional[bytes] = None) -> VerifyReport:
    """Unsealed human-readable report (report.pdf of a ZIP package)."""
    report = VerifyReport()
    report.bundle_format = "forensic-browser-report (unsealed)"
    try:
        text = "\n".join(P.extract_text(P.PDFDocument(pdf_bytes)))
    except Exception:
        text = ""
    m = re.search(r"sess-\d+", text)
    report.proof_id = m.group(0) if m else None
    report.checks.append(CheckResult(
        "report_integrity", False, skipped=True,
        detail="unsealed report — not verifiable by itself; verify the ZIP package it belongs to"))
    if original is None:
        return _finish(report, verdict=VERDICT_NOT_VERIFIABLE, notes=[
            "This is the human-readable report of a Forensic Browser ZIP package. It carries "
            "no seal. Run gpa-verify on the ZIP, or: gpa-verify report.pdf --original package.zip"])
    z = verify_fb_zip(original)
    for c in z.checks:
        report.checks.append(CheckResult(f"original.{c.name}", c.passed, c.skipped, c.detail, c.extra))
    probs = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(original))
        man = _json(zf.read("manifest.json")) or {}
        ent = (man.get("files") or {}).get("report.pdf") or {}
        if ent.get("sha256") != _sha256(pdf_bytes):
            probs.append("report differs from the package's report.pdf (manifest hash)")
    except Exception as exc:
        probs.append(f"cannot read package: {exc}")
    if report.proof_id and report.proof_id != z.proof_id:
        probs.append(f"session {report.proof_id} != package session {z.proof_id}")
    report.checks.append(CheckResult(
        "report_binding", not probs,
        detail="report is byte-identical to the package's report.pdf" if not probs else "; ".join(probs)))
    return _finish(report, notes=[
        "The report matches the package manifest. manifest.json is not time-stamped, so this "
        "shows consistency, not sealing; the evidence is the sealed files of the package."])
