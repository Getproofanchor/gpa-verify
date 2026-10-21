"""
gpa_verify.tsp_verify — strict RFC 3161 time-stamp token verification.

Used by the Forensic Browser verifiers (ZIP package and PAdES document
time-stamps). Compared with the original SaaS layer it additionally binds
the *signed attributes* to the token content:

  * signed attribute ``content-type`` must be id-ct-TSTInfo;
  * signed attribute ``message-digest`` must equal the digest of the
    encapsulated TSTInfo — without this check the CMS signature only
    proves the signed attributes are authentic, NOT the TSTInfo (and
    therefore not the imprint or genTime) they are supposed to describe;
  * ESS ``signing-certificate`` / ``signing-certificate-v2`` must
    reference the certificate actually used to verify the signature;
  * ``CMSAlgorithmProtection`` (RFC 6211), when present, must match the
    algorithms really used;
  * the signer certificate's extended key usage must be exactly
    id-kp-timeStamping and critical (RFC 3161 §2.3), and genTime must fall
    inside its validity period;
  * the issuer chain is rebuilt from the certificates available offline
    (token + optional PEM bundle) and every link's signature is checked;
  * EU Trusted List (ETSI TS 119 612) status is evaluated *at genTime*,
    using the service status history, not just the current status.

Everything is offline and deterministic.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .core import CheckResult

_HASHES = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
}


def _hash(alg: str, data: bytes) -> Optional[bytes]:
    fn = _HASHES.get(alg)
    return fn(data).digest() if fn else None


def pem_to_der_list(pem: bytes) -> List[bytes]:
    out = []
    for m in re.finditer(
        rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S
    ):
        try:
            out.append(base64.b64decode(b"".join(m.group(1).split())))
        except Exception:
            continue
    return out


@dataclass
class TokenInfo:
    """Everything learned from a token, plus the list of problems found."""
    ok: bool = False
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    status: Optional[str] = None
    gen_time: Optional[datetime] = None
    serial: Optional[int] = None
    policy: Optional[str] = None
    nonce: Optional[int] = None
    accuracy: Optional[Dict[str, Any]] = None
    tsa_name: Optional[str] = None
    imprint_alg: Optional[str] = None
    imprint_hex: Optional[str] = None
    imprint_match: Optional[bool] = None
    digest_alg: Optional[str] = None
    signature_alg: Optional[str] = None
    signer_der: Optional[bytes] = None
    signer_subject: Optional[str] = None
    signer_issuer: Optional[str] = None
    signer_serial_hex: Optional[str] = None
    signer_org: Optional[str] = None
    token_cert_ders: List[bytes] = field(default_factory=list)
    signed_attr_checks: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "gen_time": self.gen_time.isoformat() if self.gen_time else None,
            "serial": str(self.serial) if self.serial is not None else None,
            "policy_oid": self.policy,
            "nonce": str(self.nonce) if self.nonce is not None else None,
            "accuracy": self.accuracy,
            "tsa_name": self.tsa_name,
            "imprint_algorithm": self.imprint_alg,
            "imprint": self.imprint_hex,
            "imprint_match": self.imprint_match,
            "digest_algorithm": self.digest_alg,
            "signature_algorithm": self.signature_alg,
            "signer_subject": self.signer_subject,
            "signer_issuer": self.signer_issuer,
            "signer_serial": self.signer_serial_hex,
            "signed_attribute_checks": self.signed_attr_checks,
            "certificates_in_token": len(self.token_cert_ders),
        }


def _load_signed_data(blob: bytes, info: TokenInfo):
    """Accept a TimeStampResp (.tsr) or a bare TimeStampToken (ContentInfo).
    Trailing zero padding (PDF /Contents) is tolerated and reported."""
    from asn1crypto import cms, tsp

    # TimeStampResp?  SEQUENCE { PKIStatusInfo SEQUENCE, token ContentInfo }
    try:
        resp = tsp.TimeStampResp.load(blob)
        status = resp["status"]["status"].native
        _ = resp["time_stamp_token"]
        info.status = status
        if status not in ("granted", "granted_with_mods"):
            info.errors.append(f"TSA status not granted: {status}")
            return None
        tok = resp["time_stamp_token"]
        if tok.native is None:
            info.errors.append("TimeStampResp carries no token")
            return None
        ci = cms.ContentInfo.load(tok.dump())
    except Exception:
        try:
            ci = cms.ContentInfo.load(blob)
            ci.native  # force full parse
        except Exception as exc:
            info.errors.append(f"not a TimeStampResp or TimeStampToken: {exc}")
            return None
        info.status = "token"
    if ci["content_type"].native != "signed_data":
        info.errors.append(f"unexpected content type {ci['content_type'].native}")
        return None
    return ci["content"]


def _name_str(name) -> str:
    try:
        return name.human_friendly
    except Exception:
        return str(name.native)


def verify_token(
    blob: bytes,
    data: Optional[bytes] = None,
    *,
    extra_cert_ders: Iterable[bytes] = (),
) -> TokenInfo:
    """Verify an RFC 3161 token over ``data``. Never raises."""
    info = TokenInfo()
    try:
        _verify_token(blob, data, list(extra_cert_ders), info)
    except Exception as exc:  # defensive: a malformed token must not crash
        info.errors.append(f"verify exception: {type(exc).__name__}: {exc}")
    info.ok = not info.errors
    return info


def _verify_token(blob: bytes, data: Optional[bytes], extra: List[bytes], info: TokenInfo) -> None:
    from asn1crypto import tsp, x509 as ax509
    from cryptography import x509 as cx509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    sd = _load_signed_data(blob, info)
    if sd is None:
        return
    encap = sd["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        info.errors.append(f"encapsulated content is {encap['content_type'].native}, not TSTInfo")
        return
    # .contents is the OCTET STRING payload exactly as signed (the original
    # DER of TSTInfo) — never re-encode it before hashing.
    econtent = encap["content"].contents if encap["content"].native is not None else None
    if not econtent:
        info.errors.append("TSTInfo missing")
        return
    tst = tsp.TSTInfo.load(econtent)
    info.gen_time = tst["gen_time"].native
    info.serial = tst["serial_number"].native
    info.policy = tst["policy"].native
    info.nonce = tst["nonce"].native
    acc = tst["accuracy"]
    info.accuracy = acc.native if acc.native is not None else None
    if tst["tsa"].native is not None:
        try:
            info.tsa_name = _name_str(tst["tsa"].chosen)
        except Exception:
            info.tsa_name = str(tst["tsa"].native)
    mi = tst["message_imprint"]
    info.imprint_alg = mi["hash_algorithm"]["algorithm"].native
    imprint = mi["hashed_message"].native
    info.imprint_hex = imprint.hex()
    if data is not None:
        expected = _hash(info.imprint_alg, data)
        if expected is None:
            info.errors.append(f"unsupported imprint hash algorithm {info.imprint_alg}")
        else:
            info.imprint_match = expected == imprint
            if not info.imprint_match:
                info.errors.append(
                    f"message imprint mismatch: token covers {imprint.hex()[:16]}…, "
                    f"data hashes to {expected.hex()[:16]}…"
                )

    # ── signer info ──
    sis = sd["signer_infos"]
    if len(sis) != 1:
        info.errors.append(f"expected exactly one SignerInfo, found {len(sis)}")
        if len(sis) == 0:
            return
    si = sis[0]
    info.digest_alg = si["digest_algorithm"]["algorithm"].native
    sig_alg_obj = si["signature_algorithm"]
    info.signature_alg = sig_alg_obj["algorithm"].native

    certs: List[ax509.Certificate] = []
    if sd["certificates"] is not None:
        for c in sd["certificates"]:
            if isinstance(c.chosen, ax509.Certificate):
                certs.append(c.chosen)
    info.token_cert_ders = [c.dump() for c in certs]
    pool = list(certs)
    for der in extra:
        try:
            pool.append(ax509.Certificate.load(der))
        except Exception:
            continue

    sid = si["sid"]
    signer = None
    for c in pool:
        try:
            if sid.name == "issuer_and_serial_number":
                if c.issuer == sid.chosen["issuer"] and c.serial_number == sid.chosen["serial_number"].native:
                    signer = c
                    break
            elif sid.name == "subject_key_identifier":
                if c.key_identifier == sid.chosen.native:
                    signer = c
                    break
        except Exception:
            continue
    if signer is None:
        info.errors.append("signer certificate (SignerIdentifier) not found in token or supplied certificates")
        return
    info.signer_der = signer.dump()
    info.signer_subject = _name_str(signer.subject)
    info.signer_issuer = _name_str(signer.issuer)
    info.signer_serial_hex = format(signer.serial_number, "x")
    try:
        info.signer_org = signer.subject.native.get("organization_name")
    except Exception:
        info.signer_org = None
    if info.signer_der not in info.token_cert_ders:
        info.notes.append("signer certificate was not embedded in the token; taken from supplied certificates")

    # ── signed attributes ──
    sa = si["signed_attrs"]
    if not sa or sa.native is None or len(sa) == 0:
        info.errors.append("no signed attributes (RFC 3161 requires them)")
        return
    attrs: Dict[str, List[Any]] = {}
    for a in sa:
        attrs.setdefault(a["type"].native, []).append(a["values"])
    chk = info.signed_attr_checks

    ct = attrs.get("content_type")
    if not ct or len(ct) != 1 or ct[0][0].native != "tst_info":
        chk["content_type"] = "fail"
        info.errors.append("signed attribute content-type is not id-ct-TSTInfo")
    else:
        chk["content_type"] = "ok"

    md = attrs.get("message_digest")
    want = _hash(info.digest_alg, econtent)
    if want is None:
        info.errors.append(f"unsupported digest algorithm {info.digest_alg}")
        chk["message_digest"] = "fail"
    elif not md or len(md) != 1 or md[0][0].native != want:
        chk["message_digest"] = "fail"
        info.errors.append(
            "signed attribute message-digest does not match the TSTInfo — the "
            "token content was altered after signing"
        )
    else:
        chk["message_digest"] = "ok"

    # ESS signing-certificate(-v2)
    sc2 = attrs.get("signing_certificate_v2")
    sc1 = attrs.get("signing_certificate")
    if sc2:
        cid = sc2[0][0]["certs"][0]
        halg = cid["hash_algorithm"]["algorithm"].native if cid["hash_algorithm"].native else "sha256"
        good = _hash(halg, info.signer_der) == cid["cert_hash"].native
        if good and cid["issuer_serial"].native is not None:
            good = cid["issuer_serial"]["serial_number"].native == signer.serial_number
        chk["signing_certificate_v2"] = "ok" if good else "fail"
        if not good:
            info.errors.append("ESS signing-certificate-v2 does not reference the signer certificate")
    elif sc1:
        cid = sc1[0][0]["certs"][0]
        good = hashlib.sha1(info.signer_der).digest() == cid["cert_hash"].native
        chk["signing_certificate"] = "ok" if good else "fail"
        if not good:
            info.errors.append("ESS signing-certificate does not reference the signer certificate")
    else:
        chk["signing_certificate"] = "missing"
        info.errors.append("no ESS signing-certificate attribute (required by RFC 3161 / RFC 5816)")

    cap = attrs.get("cms_algorithm_protection")
    if cap:
        try:
            v = cap[0][0]
            ok = v["digest_algorithm"]["algorithm"].native == info.digest_alg
            sa_alg = v["signature_algorithm"]
            if sa_alg.native is not None:
                ok = ok and sa_alg["algorithm"].native == info.signature_alg
            chk["cms_algorithm_protection"] = "ok" if ok else "fail"
            if not ok:
                info.errors.append("CMSAlgorithmProtection does not match the algorithms used")
        except Exception:
            chk["cms_algorithm_protection"] = "unparsed"

    # ── signature ──
    sattrs_der = sa.dump()
    if sattrs_der[:1] == b"\xa0":
        sattrs_der = b"\x31" + sattrs_der[1:]
    hmap = {"sha1": hashes.SHA1(), "sha224": hashes.SHA224(), "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
    halg = hmap.get(info.digest_alg)
    cert = cx509.load_der_x509_certificate(info.signer_der)
    pub = cert.public_key()
    sig = si["signature"].native
    sname = info.signature_alg or ""
    try:
        if sname == "rsassa_pss":
            params = sig_alg_obj["parameters"]
            ph = hmap.get(params["hash_algorithm"]["algorithm"].native, halg)
            mgf_h = hmap.get(params["mask_gen_algorithm"]["parameters"]["algorithm"].native, ph)
            salt = params["salt_length"].native
            pub.verify(sig, sattrs_der, padding.PSS(mgf=padding.MGF1(mgf_h), salt_length=salt), ph)
        elif isinstance(pub, rsa.RSAPublicKey):
            if halg is None:
                raise ValueError(f"unsupported digest {info.digest_alg}")
            m = re.match(r"(sha\d+)_rsa$", sname)
            if m and m.group(1) != info.digest_alg:
                info.errors.append(f"signature algorithm {sname} disagrees with digest {info.digest_alg}")
            pub.verify(sig, sattrs_der, padding.PKCS1v15(), halg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if halg is None:
                raise ValueError(f"unsupported digest {info.digest_alg}")
            pub.verify(sig, sattrs_der, ec.ECDSA(halg))
        else:
            from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
            if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                pub.verify(sig, sattrs_der)
            else:
                raise ValueError(f"unsupported key type {type(pub).__name__}")
        chk["signature"] = "ok"
    except InvalidSignature:
        chk["signature"] = "fail"
        info.errors.append("CMS signature is INVALID")
    except Exception as exc:
        chk["signature"] = "fail"
        info.errors.append(f"signature verification error: {exc}")

    # ── signer certificate profile ──
    try:
        ext = cert.extensions.get_extension_for_class(cx509.ExtendedKeyUsage)
        eku = list(ext.value)
        if eku != [cx509.oid.ExtendedKeyUsageOID.TIME_STAMPING]:
            info.errors.append("signer EKU is not exactly id-kp-timeStamping")
        elif not ext.critical:
            info.errors.append("signer timeStamping EKU is not marked critical (RFC 3161 §2.3)")
        else:
            chk["eku_timestamping_critical"] = "ok"
    except cx509.ExtensionNotFound:
        info.errors.append("signer certificate has no extended key usage")
    if info.gen_time is not None:
        nb = _cert_time(cert, "not_valid_before")
        na = _cert_time(cert, "not_valid_after")
        gt = info.gen_time if info.gen_time.tzinfo else info.gen_time.replace(tzinfo=timezone.utc)
        if not (nb <= gt <= na):
            info.errors.append(
                f"genTime {gt.isoformat()} outside signer certificate validity "
                f"{nb.isoformat()} … {na.isoformat()}"
            )
        else:
            chk["gen_time_within_cert_validity"] = "ok"
    if info.tsa_name and info.signer_subject and info.tsa_name != info.signer_subject:
        info.notes.append("TSTInfo.tsa name differs from signer certificate subject")


def _cert_time(cert, attr: str) -> datetime:
    v = getattr(cert, attr + "_utc", None)
    if v is None:  # cryptography < 42
        v = getattr(cert, attr).replace(tzinfo=timezone.utc)
    return v


# ─────────────────────────────────────────────────────────────────────────────
# Chain building
# ─────────────────────────────────────────────────────────────────────────────

def build_chain(signer_der: bytes, pool_ders: Iterable[bytes],
                at: Optional[datetime] = None) -> Dict[str, Any]:
    """Rebuild issuer chain from the available certs; verify each link."""
    from cryptography import x509 as cx509

    pool = []
    seen = set()
    for d in pool_ders:
        h = hashlib.sha256(d).digest()
        if h in seen:
            continue
        seen.add(h)
        try:
            pool.append(cx509.load_der_x509_certificate(d))
        except Exception:
            continue
    cur = cx509.load_der_x509_certificate(signer_der)
    chain = [cur]
    errors: List[str] = []
    complete = False
    for _ in range(10):
        if cur.issuer == cur.subject:
            try:
                cur.verify_directly_issued_by(cur)
                complete = True
            except Exception:
                errors.append(f"self-signed certificate {cur.subject.rfc4514_string()} has a bad signature")
            break
        issuer = None
        for c in pool:
            if c.subject == cur.issuer and c is not cur:
                try:
                    cur.verify_directly_issued_by(c)
                    issuer = c
                    break
                except Exception:
                    continue
        if issuer is None:
            break
        chain.append(issuer)
        cur = issuer
    if at is not None:
        gt = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        for c in chain:
            if not (_cert_time(c, "not_valid_before") <= gt <= _cert_time(c, "not_valid_after")):
                errors.append(f"{c.subject.rfc4514_string()} not valid at {gt.isoformat()}")
    return {
        "complete": complete,
        "errors": errors,
        "subjects": [c.subject.rfc4514_string() for c in chain],
        "sha256": [hashlib.sha256(c.public_bytes(_der_enc())).hexdigest() for c in chain],
        "ders": [c.public_bytes(_der_enc()) for c in chain],
    }


def _cn(rfc4514: str) -> str:
    m = re.search(r"(?:^|,)CN=([^,]+)", rfc4514)
    return m.group(1) if m else rfc4514


def _der_enc():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


# ─────────────────────────────────────────────────────────────────────────────
# EU Trusted List (ETSI TS 119 612)
# ─────────────────────────────────────────────────────────────────────────────

_TSL_NS = "http://uri.etsi.org/02231/v2#"
_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
_GRANTED = {
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    # pre-eIDAS status values, treated as qualified for historic genTimes
    "http://uri.etsi.org/TrstSvc/Svcstatus/accredited",
    "http://uri.etsi.org/TrstSvc/Svcstatus/undersupervision",
}


def _parse_dt(s: str) -> Optional[datetime]:
    try:
        s = s.strip().replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_tsl_qtst(xml_bytes: bytes) -> Dict[str, Any]:
    """Return {'territory', 'issue', 'next_update', 'services': [...]} where each
    service is {'name','certs': set(sha256), 'statuses': [(start, status)]}."""
    import xml.etree.ElementTree as ET

    ns = "{" + _TSL_NS + "}"
    root = ET.fromstring(xml_bytes)
    if not root.tag.endswith("TrustServiceStatusList"):
        raise ValueError("root element is not TrustServiceStatusList")
    sch = root.find(ns + "SchemeInformation")
    territory = sch.findtext(ns + "SchemeTerritory") if sch is not None else None
    issue = sch.findtext(ns + "ListIssueDateTime") if sch is not None else None
    nxt = None
    if sch is not None:
        nu = sch.find(ns + "NextUpdate")
        if nu is not None:
            nxt = nu.findtext(ns + "dateTime")
    services = []
    for svc in root.iter(ns + "TSPService"):
        si = svc.find(ns + "ServiceInformation")
        if si is None:
            continue
        stype = si.findtext(ns + "ServiceTypeIdentifier", default="")
        if stype != _QTST:
            continue
        nm = si.find(f"{ns}ServiceName/{ns}Name")
        name = (nm.text if nm is not None else None) or "?"
        statuses = [(_parse_dt(si.findtext(ns + "StatusStartingTime", default="")),
                     si.findtext(ns + "ServiceStatus", default=""))]
        hist = svc.find(ns + "ServiceHistory")
        if hist is not None:
            for h in hist.findall(ns + "ServiceHistoryInstance"):
                if h.findtext(ns + "ServiceTypeIdentifier", default=_QTST) != _QTST:
                    continue
                statuses.append((_parse_dt(h.findtext(ns + "StatusStartingTime", default="")),
                                 h.findtext(ns + "ServiceStatus", default="")))
        certs = set()
        for el in si.iter(ns + "X509Certificate"):
            b64 = "".join((el.text or "").split())
            try:
                certs.add(hashlib.sha256(base64.b64decode(b64)).hexdigest())
            except Exception:
                continue
        services.append({"name": name, "certs": certs, "statuses": statuses})
    return {"territory": territory, "issue": issue, "next_update": nxt, "services": services}


def status_at(statuses: List[Tuple[Optional[datetime], str]], when: Optional[datetime]) -> Tuple[Optional[str], Optional[datetime]]:
    dated = [(s, st) for s, st in statuses if s is not None]
    if when is None or not dated:
        return (statuses[0][1] if statuses else None), (statuses[0][0] if statuses else None)
    w = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    best = None
    for s, st in dated:
        if s <= w and (best is None or s > best[0]):
            best = (s, st)
    if best is None:
        return None, None
    return best[1], best[0]


def check_tsl(
    chain_ders: List[bytes],
    tsl_files: List[Tuple[str, bytes]],
    gen_time: Optional[datetime],
    *,
    name: str = "tsl_qualified",
    missing_detail: str = "no EU Trusted List available offline — qualified status not checked",
) -> CheckResult:
    if not tsl_files:
        return CheckResult(name=name, passed=False, skipped=True, detail=missing_detail)
    if not chain_ders:
        return CheckResult(name=name, passed=False, detail="no signer certificate to look up")
    hashes = [hashlib.sha256(d).hexdigest() for d in chain_ders]
    parsed = []
    for fname, raw in tsl_files:
        try:
            t = parse_tsl_qtst(raw)
        except Exception as exc:
            return CheckResult(name=name, passed=False,
                               detail=f"cannot parse Trusted List {fname}: {type(exc).__name__}: {exc}")
        t["file"] = fname
        t["sha256"] = hashlib.sha256(raw).hexdigest()
        parsed.append(t)
    for t in parsed:
        for svc in t["services"]:
            for idx, h in enumerate(hashes):
                if h not in svc["certs"]:
                    continue
                st, since = status_at(svc["statuses"], gen_time)
                extra = {
                    "service_name": svc["name"],
                    "service_type": "TSA/QTST",
                    "status_at_gen_time": st,
                    "status_since": since.isoformat() if since else None,
                    "matched_sha256": h,
                    "matched_on_leaf": idx == 0,
                    "tsl_file": t["file"],
                    "tsl_sha256": t["sha256"],
                    "tsl_territory": t["territory"],
                    "tsl_issued": t["issue"],
                }
                if st in _GRANTED:
                    return CheckResult(
                        name=name, passed=True,
                        detail=(f"listed as granted Qualified Time-Stamping service at genTime "
                                f"in {t['territory'] or '?'} Trusted List ({svc['name']})"
                                + ("" if idx == 0 else " [matched via chain certificate]")),
                        extra=extra,
                    )
                return CheckResult(
                    name=name, passed=False,
                    detail=f"service found ({svc['name']}) but status at genTime is {st or 'unknown'}",
                    extra=extra,
                )
    return CheckResult(
        name=name, passed=False,
        detail="TSA certificate NOT listed under any TSA/QTST service in the supplied Trusted List(s)",
        extra={"signer_sha256": hashes[0], "tsl_files": [t["file"] for t in parsed]},
    )


def token_checks(
    info: TokenInfo,
    *,
    pool_ders: Iterable[bytes] = (),
    tsl_files: List[Tuple[str, bytes]],
    name_prefix: str = "",
    tsl_missing_detail: str = "no EU Trusted List available offline — qualified status not checked",
) -> List[CheckResult]:
    """Turn a TokenInfo into the standard checks:
    timestamp_token, tsa_chain, tsa_trust_root, tsl_qualified."""
    out: List[CheckResult] = []
    s = info.summary()
    if info.ok:
        m = re.search(r"Common Name: ([^,]+)", info.signer_subject or "")
        who = m.group(1) if m else info.signer_subject
        detail = (f"valid RFC 3161 token from {who}, genTime="
                  f"{s['gen_time']}, serial={s['serial']}, policy={info.policy}")
    else:
        detail = "; ".join(info.errors[:3])
    out.append(CheckResult(
        name=f"{name_prefix}timestamp_token", passed=info.ok, detail=detail,
        extra={**s, **({"errors": info.errors} if info.errors else {}),
               **({"notes": info.notes} if info.notes else {})},
    ))
    if not info.signer_der:
        out.append(CheckResult(name=f"{name_prefix}tsa_chain", passed=False, skipped=True,
                               detail="no signer certificate"))
        out.append(CheckResult(name=f"{name_prefix}tsl_qualified", passed=False, skipped=True,
                               detail="no signer certificate"))
        return out
    from .trust import KNOWN_INTERMEDIATES, PINNED_ROOTS
    ch = build_chain(info.signer_der,
                     list(info.token_cert_ders) + list(pool_ders) + KNOWN_INTERMEDIATES
                     + [d for _, d in PINNED_ROOTS],
                     info.gen_time)
    if ch["errors"]:
        out.append(CheckResult(name=f"{name_prefix}tsa_chain", passed=False,
                               detail="; ".join(ch["errors"]), extra={"chain": ch["subjects"]}))
    elif ch["complete"]:
        out.append(CheckResult(
            name=f"{name_prefix}tsa_chain", passed=True,
            detail=f"{len(ch['subjects'])}-certificate chain to self-signed root "
                   f"{_cn(ch['subjects'][-1])}, every link signature valid at genTime",
            extra={"chain": ch["subjects"], "chain_sha256": ch["sha256"]}))
    else:
        out.append(CheckResult(
            name=f"{name_prefix}tsa_chain", passed=False, skipped=True,
            detail=(f"issuer of {_cn(ch['subjects'][-1])} not available offline — chain not "
                    "built (qualified status below is decided by the Trusted List)"),
            extra={"chain": ch["subjects"]}))
    from .trust import check_trust_root
    out.append(check_trust_root(info.signer_der, list(info.token_cert_ders) + list(pool_ders),
                                info.gen_time, name=f"{name_prefix}tsa_trust_root"))
    out.append(check_tsl(ch["ders"], tsl_files, info.gen_time,
                         name=f"{name_prefix}tsl_qualified", missing_detail=tsl_missing_detail))
    return out
