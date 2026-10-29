"""
gpa_verify.cli — command-line interface.

Usage:
    gpa-verify path/to/evidence.zip
    gpa-verify --json path/to/evidence.zip > report.json
    gpa-verify --quiet path/to/evidence.zip ; echo $?
    gpa-verify sealed.pdf [--tsl EE.xml|dir|package.zip]
    gpa-verify plain-copy_bez-pecete.pdf --original sealed.pdf
    gpa-verify sealed.pdf --media sealed_media.zip   (FB video & audio, 1.7.2)

Input kind is auto-detected: SaaS evidence ZIP, Forensic Browser ZIP,
PAdES-sealed PDF, or unsealed plain copy / report PDF.

Exit codes:
    0  — VERIFIED: no check failed and a qualified timestamp verified
    1  — FAILED: at least one check failed
    2  — invalid arguments / cannot read input
    3  — NOT VERIFIABLE BY ITSELF: unsealed plain copy, unsealed report.pdf or companion media archive
         (with or without --original)
    4  — INTEGRITY ONLY (1.7.1): no check failed, but the package carries no
         verified qualified timestamp; the files are only consistent with
         manifest.json, which anyone can recompute
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from .core import INTEGRITY_ONLY_TEXT, VerifyReport
from .dispatch import verify_bytes


# ANSI colour helpers — NO_COLOR / non-TTY auto-disable
def _supports_color(stream: TextIO) -> bool:
    if "NO_COLOR" in __import__("os").environ:
        return False
    return getattr(stream, "isatty", lambda: False)()


class _Colors:
    def __init__(self, enabled: bool):
        if enabled:
            self.green   = "\033[32m"
            self.red     = "\033[31m"
            self.yellow  = "\033[33m"
            self.dim     = "\033[2m"
            self.bold    = "\033[1m"
            self.reset   = "\033[0m"
        else:
            self.green = self.red = self.yellow = self.dim = self.bold = self.reset = ""


def _print_human(report: VerifyReport, stream: TextIO, colors: _Colors) -> None:
    c = colors
    print(file=stream)
    print(f"{c.bold}GetProofAnchor Evidence Verifier{c.reset}", file=stream)
    print(f"{c.dim}{'─' * 64}{c.reset}", file=stream)
    print(f"  Proof ID:       {report.proof_id or '—'}", file=stream)
    print(f"  Bundle format:  {report.bundle_format or '—'}", file=stream)
    print(f"  Generated at:   {report.generated_at or '—'}", file=stream)
    print(file=stream)

    for check in report.checks:
        if check.skipped:
            tag = f"{c.yellow}SKIP{c.reset}"
        elif check.passed and check.informational:
            tag = f"{c.dim}INFO{c.reset}"
        elif check.passed:
            tag = f"{c.green}PASS{c.reset}"
        else:
            tag = f"{c.red}FAIL{c.reset}"
        print(f"  [{tag}]  {check.name}", file=stream)
        if check.detail:
            print(f"          {c.dim}{check.detail}{c.reset}", file=stream)
        if not check.passed and not check.skipped and check.extra:
            for k, v in check.extra.items():
                if k == "mismatches" and isinstance(v, list):
                    for item in v[:5]:
                        print(f"          {c.dim}↳ {item}{c.reset}", file=stream)
                elif isinstance(v, (str, int, float, bool)) or v is None:
                    print(f"          {c.dim}↳ {k}: {v}{c.reset}", file=stream)
        print(file=stream)

    s = report.summary
    if "sealed" in s or "not_sealed" in s:
        _print_sealed(s, stream, c)
    if s.get("message"):
        print(f"  {c.yellow}{c.bold}{s['message']}{c.reset}", file=stream)
        print(file=stream)

    if s.get("verdict") == "VERIFIED":
        verdict_line = f"{c.green}{c.bold}✓ VERIFIED{c.reset}"
    elif s.get("verdict") == "NOT_VERIFIABLE":
        verdict_line = f"{c.yellow}{c.bold}? NOT VERIFIABLE BY ITSELF{c.reset}"
    elif s.get("verdict") == "INTEGRITY_ONLY":
        verdict_line = f"{c.yellow}{c.bold}! INTEGRITY ONLY — {INTEGRITY_ONLY_TEXT}{c.reset}"
    else:
        verdict_line = f"{c.red}{c.bold}✗ FAILED{c.reset}"

    info = f", {s['checks_info']} info" if s.get("checks_info") else ""
    print(f"{c.dim}{'─' * 64}{c.reset}", file=stream)
    print(
        f"  {verdict_line}  "
        f"({s.get('checks_passed', 0)} passed, "
        f"{s.get('checks_failed', 0)} failed, "
        f"{s.get('checks_skipped', 0)} skipped{info})",
        file=stream,
    )
    q = s.get("qualified")
    if q and s.get("verdict") == "VERIFIED":
        label = {"per_supplied_tsl": "qualified per the supplied Trusted List (list signature not verified)",
                 "not_checked": f"{c.yellow}qualified (eIDAS) status NOT checked{c.reset} — use --tsl",
                 "failed": "not qualified"}.get(q, q)
        print(f"  Time-stamp:     {label}", file=stream)
    print(file=stream)
    for note in s.get("notes") or []:
        print(f"  {c.dim}• {note}{c.reset}", file=stream)
    if s.get("notes"):
        print(file=stream)

    if report.summary.get("verdict") == "FAILED":
        print(
            f"  {c.dim}For full details, re-run with --json | jq{c.reset}",
            file=stream,
        )
        print(file=stream)


def _print_sealed(s: dict, stream: TextIO, c: _Colors) -> None:
    """1.7.1: the facts sealed by the qualified timestamp, so that a reader can
    compare report.pdf / proof.json with them, and what is NOT sealed."""
    sealed = s.get("sealed")
    if not sealed:
        print(f"{c.bold}Sealed facts:{c.reset} {c.yellow}none — this package has no verified "
              f"qualified timestamp, so nothing in it is sealed{c.reset}", file=stream)
    else:
        print(f"{c.bold}Sealed facts{c.reset} {c.dim}(from timestamp/eidas_payload.json, "
              f"bound by the verified qualified timestamp){c.reset}", file=stream)
        mode = sealed.get("capture_mode")
        mode_txt = {"browser": "browser (GetProofAnchor browser extension)",
                    "server": "server (captured by GetProofAnchor's own browser)",
                    "file_digest": "file_digest (certified file digest)"}.get(mode, mode)
        rows = [
            ("Proof ID", sealed.get("proof_id")),
            ("Source URL", sealed.get("source_url")),
            ("Final URL", sealed.get("final_url")),
            ("Captured at", sealed.get("captured_at")),
            ("Time-stamped", sealed.get("timestamp_gen_time")),
            ("Capture mode", (f"{mode_txt}  [{sealed.get('capture_mode_basis')}]" if mode
                              else "not sealed (capture/capture_meta.json is not bound by the payload)")),
        ]
        for k, v in rows:
            print(f"  {k + ':':<15} {v if v not in (None, '') else '—'}", file=stream)
        if sealed.get("capture_note"):
            print(f"  {c.yellow}! {sealed['capture_note']}{c.reset}", file=stream)
        files = sealed.get("sealed_files") or []
        print(f"  {'Sealed files:':<15} {', '.join(files)}", file=stream)
    ns = s.get("not_sealed") or {}
    gen = ns.get("generated_at_download") or []
    helpers = ns.get("timestamp_helpers") or []
    other = ns.get("other") or []
    if gen or helpers:
        parts = list(gen) + ([f"timestamp helper files ({len(helpers)})"] if helpers else [])
        print(f"  {c.bold}NOT sealed{c.reset} (generated at download time): {', '.join(parts)}",
              file=stream)
    if other:
        shown = ", ".join(other[:8]) + (f" … (+{len(other) - 8})" if len(other) > 8 else "")
        print(f"  {c.bold}NOT sealed{c.reset} by the qualified timestamp (other): {shown}", file=stream)
    print(file=stream)


_EPILOG = """exit codes:
  0  VERIFIED — no check failed and a qualified timestamp verified
  1  FAILED — at least one check failed
  2  invalid arguments / cannot read input
  3  NOT VERIFIABLE BY ITSELF — unsealed plain copy, unsealed report.pdf or companion media archive
  4  INTEGRITY ONLY — no check failed, but there is no verified qualified
     timestamp: the files are only consistent with manifest.json, which
     anyone can recompute

https://github.com/getproofanchor/gpa-verify
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gpa-verify",
        description=(
            "Independently verify a GetProofAnchor evidence bundle (SaaS ZIP), "
            "a Forensic Browser ZIP package, a PAdES-sealed Forensic Browser PDF "
            "or an unsealed plain copy. Reads ONLY the given files — no network, "
            "no GetProofAnchor servers required."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "zip_path",
        type=Path,
        metavar="FILE",
        help="evidence ZIP (SaaS or Forensic Browser) or Forensic Browser PDF",
    )
    parser.add_argument(
        "--original",
        type=Path,
        metavar="FILE",
        default=None,
        help=(
            "for an unsealed plain copy (…_bez-pecete.pdf): the sealed original "
            "PDF it identifies; for an unsealed report.pdf (Forensic Browser or "
            "SaaS): its ZIP package — the report is compared with the package "
            "manifest (never a VERIFIED verdict for a report)"
        ),
    )
    parser.add_argument(
        "--media",
        type=Path,
        metavar="ZIP",
        default=None,
        help=(
            "for a sealed Forensic Browser PDF whose video/audio was too large to "
            "embed: the companion archive (…_media.zip) delivered with it; every "
            "media file is checked against the SHA-256 sealed in the PDF"
        ),
    )
    parser.add_argument(
        "--tsl",
        action="append",
        metavar="PATH",
        default=[],
        help=(
            "EU Trusted List for sealed PDFs (which embed none): a TSL .xml, a "
            "directory of them, or a Forensic Browser/SaaS ZIP whose "
            "timestamp/tsl/*.xml is used. Repeatable."
        ),
    )
    parser.add_argument(
        "--certs",
        action="append",
        metavar="PEM",
        default=[],
        help="extra TSA CA certificates (PEM) for building the TSA chain. Repeatable.",
    )
    parser.add_argument(
        "--trust-root",
        action="append",
        metavar="PEM",
        default=[],
        help=(
            "additional root certificate the TSA chain may end in (PEM or DER). "
            "By default only the SK ID Solutions roots pinned inside gpa-verify "
            "are trusted. Repeatable."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit full machine-readable JSON report on stdout",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="emit nothing on success; emit failures on stderr",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour output",
    )
    parser.add_argument(
        "--bitcoin-rpc",
        metavar="URL",
        default=None,
        help=(
            "Bitcoin Core JSON-RPC URL of a node YOU operate "
            "(e.g. http://user:pass@127.0.0.1:8332). Enables REAL Bitcoin "
            "block verification of the OTS receipt against your own node — "
            "no calendars, no explorers, receipt never modified. Without this "
            "flag the tool is fully offline and reports Bitcoin status from "
            "the manifest only."
        ),
    )
    args = parser.parse_args(argv)

    if not args.zip_path.exists():
        print(f"error: file not found: {args.zip_path}", file=sys.stderr)
        return 2
    if not args.zip_path.is_file():
        print(f"error: not a regular file: {args.zip_path}", file=sys.stderr)
        return 2

    try:
        zip_bytes = args.zip_path.read_bytes()
    except OSError as exc:
        print(f"error: cannot read {args.zip_path}: {exc}", file=sys.stderr)
        return 2

    original = None
    for p in ([args.original] if args.original else []) + ([args.media] if args.media else []):
        if not p.is_file():
            print(f"error: file not found: {p}", file=sys.stderr)
            return 2
    for p in list(args.tsl) + list(args.certs) + list(args.trust_root):
        if not Path(p).exists():
            print(f"error: file not found: {p}", file=sys.stderr)
            return 2
    try:
        if args.original:
            original = args.original.read_bytes()
        _kind, report = verify_bytes(
            zip_bytes,
            original=original,
            original_name=args.original.name if args.original else None,
            tsl_paths=[str(p) for p in args.tsl],
            cert_paths=[str(p) for p in args.certs],
            trust_root_paths=[str(p) for p in args.trust_root],
            bitcoin_rpc=args.bitcoin_rpc,
            media=args.media.read_bytes() if args.media else None,
        )
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    verdict = report.summary.get("verdict")
    not_verifiable = verdict == "NOT_VERIFIABLE"
    integrity_only = verdict == "INTEGRITY_ONLY"
    if args.original and _kind not in ("plain_copy", "fb_report", "saas_report", "fb_media_zip"):
        print(f"warning: --original is ignored for this input ({_kind})", file=sys.stderr)
    if args.media and _kind != "sealed_pdf":
        print(f"warning: --media is ignored for this input ({_kind})", file=sys.stderr)
    if args.bitcoin_rpc and _kind not in ("saas_zip", "zip_unknown"):
        print(f"warning: --bitcoin-rpc is ignored for this input ({_kind})", file=sys.stderr)

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    elif args.quiet:
        if report.any_failed:
            for c in report.checks:
                if not c.passed and not c.skipped:
                    print(f"FAIL  {c.name}: {c.detail}", file=sys.stderr)
        elif not_verifiable:
            msg = ("unsealed SaaS report — verify its Evidence ZIP instead"
                   if _kind == "saas_report" else
                   "companion media archive — run: gpa-verify <sealed PDF> --media <this archive>"
                   if _kind == "fb_media_zip" else "unsealed copy — pass --original <sealed file>")
            print(f"NOT VERIFIABLE: {msg}", file=sys.stderr)
        elif integrity_only:
            print(f"INTEGRITY ONLY: {INTEGRITY_ONLY_TEXT}", file=sys.stderr)
    else:
        colors = _Colors(
            enabled=not args.no_color and _supports_color(sys.stdout)
        )
        _print_human(report, sys.stdout, colors)

    return exit_code(report)


def exit_code(report: VerifyReport) -> int:
    """0 VERIFIED, 1 FAILED, 3 NOT VERIFIABLE BY ITSELF, 4 INTEGRITY ONLY."""
    verdict = report.summary.get("verdict")
    if report.any_failed or verdict == "FAILED":
        return 1
    if verdict == "NOT_VERIFIABLE":
        return 3
    if verdict == "INTEGRITY_ONLY":
        return 4
    return 0 if verdict == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
