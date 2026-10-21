"""
gpa_verify.cli — command-line interface.

Usage:
    gpa-verify path/to/evidence.zip
    gpa-verify --json path/to/evidence.zip > report.json
    gpa-verify --quiet path/to/evidence.zip ; echo $?
    gpa-verify sealed.pdf [--tsl EE.xml|dir|package.zip]
    gpa-verify plain-copy_bez-pecete.pdf --original sealed.pdf

Input kind is auto-detected: SaaS evidence ZIP, Forensic Browser ZIP,
PAdES-sealed PDF, or unsealed plain copy / report PDF.

Exit codes:
    0  — all checks passed (or skipped)
    1  — at least one check failed
    2  — invalid arguments / cannot read input
    3  — input is not verifiable by itself (unsealed copy without --original)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from .core import VerifyReport
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
    if s.get("verdict") == "VERIFIED":
        verdict_line = f"{c.green}{c.bold}✓ VERIFIED{c.reset}"
    elif s.get("verdict") == "NOT_VERIFIABLE":
        verdict_line = f"{c.yellow}{c.bold}? NOT VERIFIABLE BY ITSELF{c.reset}"
    else:
        verdict_line = f"{c.red}{c.bold}✗ FAILED{c.reset}"

    print(f"{c.dim}{'─' * 64}{c.reset}", file=stream)
    print(
        f"  {verdict_line}  "
        f"({s.get('checks_passed', 0)} passed, "
        f"{s.get('checks_failed', 0)} failed, "
        f"{s.get('checks_skipped', 0)} skipped)",
        file=stream,
    )
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gpa-verify",
        description=(
            "Independently verify a GetProofAnchor evidence bundle (SaaS ZIP), "
            "a Forensic Browser ZIP package, a PAdES-sealed Forensic Browser PDF "
            "or an unsealed plain copy. Reads ONLY the given files — no network, "
            "no GetProofAnchor servers required."
        ),
        epilog="https://github.com/getproofanchor/gpa-verify",
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
            "PDF it identifies; for an unsealed report.pdf: its ZIP package"
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
    for p in [args.original] if args.original else []:
        if not p.is_file():
            print(f"error: file not found: {p}", file=sys.stderr)
            return 2
    for p in list(args.tsl) + list(args.certs):
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
            bitcoin_rpc=args.bitcoin_rpc,
        )
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    not_verifiable = report.summary.get("verdict") == "NOT_VERIFIABLE"

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    elif args.quiet:
        if report.any_failed:
            for c in report.checks:
                if not c.passed and not c.skipped:
                    print(f"FAIL  {c.name}: {c.detail}", file=sys.stderr)
        elif not_verifiable:
            print("NOT VERIFIABLE: unsealed copy — pass --original <sealed file>",
                  file=sys.stderr)
    else:
        colors = _Colors(
            enabled=not args.no_color and _supports_color(sys.stdout)
        )
        _print_human(report, sys.stdout, colors)

    if report.any_failed:
        return 1
    return 3 if not_verifiable else 0


if __name__ == "__main__":
    sys.exit(main())
