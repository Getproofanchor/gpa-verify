"""
gpa_verify.trust — pinned trust anchors for the TSA certificate chain (1.6.0).

Why: a Trusted List bundled inside an evidence file is supplied by the same
party as the timestamp. Offline, a forger could ship a self-made TSA *and* a
self-made TSL. The ``tsa_trust_root`` check closes that gap: the TSA signer
certificate must chain, link by link, to one of the root certificates pinned
below (shipped inside this package, independent of the evidence file).

Pinned by default — the CA hierarchy of SK ID Solutions AS (Estonia), the
qualified trust service provider whose TSA GetProofAnchor and Forensic
Browser use. Fingerprints (SHA-256 of the DER certificate) were checked
against https://c.sk.ee/ and against the production chain
(SK TIMESTAMPING UNIT 2026R ← SK TSA CA 2023R ← ROOT G1R).

Other roots (another QTSP, or a test CA) can be added per run with
``gpa-verify --trust-root root.pem`` or ``trust_roots=[...]`` in the API.
"""

from __future__ import annotations

import contextlib
import hashlib
from contextvars import ContextVar
from datetime import datetime
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .core import CheckResult

# name, SHA-256 fingerprint of DER, PEM
_PINNED: Tuple[Tuple[str, str, str], ...] = (
    (
        "SK ID Solutions ROOT G1R",
        "d012da1a62193928c5b4d89d2a72495b1f77ea5d54f23956bc1df2f75528fefb",
        """-----BEGIN CERTIFICATE-----
MIIFuTCCA6GgAwIBAgIQdGXMmxhPDu1hWuq15s9LKTANBgkqhkiG9w0BAQwFADBm
MQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYD
VQRhDA5OVFJFRS0xMDc0NzAxMzEhMB8GA1UEAwwYU0sgSUQgU29sdXRpb25zIFJP
T1QgRzFSMB4XDTIxMTAwNDExNTExN1oXDTQxMTAwNDExNTExN1owZjELMAkGA1UE
BhMCRUUxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzEXMBUGA1UEYQwOTlRS
RUUtMTA3NDcwMTMxITAfBgNVBAMMGFNLIElEIFNvbHV0aW9ucyBST09UIEcxUjCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL7mnRyYj4tyd8hvdY3RKvbR
CDa70qUX+bi6GV081Y40QlpNvbZiB/Q31bMxOuHMZ9qmMktJyAS4d3LXaOsvrJT3
kVg9Wk9+SJ071pMT4jKdelFR0e4pIM28DwLsfQ9n32kCyOTbSLz0cZ8RnZUW3Yk8
qX2ORnFtn/oscJW4EWCBOh3hYlIK8MEyDqNr5MByrZ9Ew5LebDYxeOqa1KereTXV
rF8RmWYpuXGuuMen5ujZtBjaF2LlSsb/chX4PtapgUZKLHVfPjVlpBlx1IAKcQCW
orB/vqQeeBqGzLimlG7FiSA1IodYMQCncXqcY/Z/nbQTSNkRJd6xHVzCVJv6EqlW
6lVnak6nJ5uCyITlVj3/oDxODiNe3Sc14/vPu4YvjX1U9NsNuC4VZiScarTSbgph
i/TWmFkX3Cvyb1abBNJSbN7R7R4An49Wl28uN87h7mu7HydcCF0Urqm1kjLryK7Y
0ApGD5v6U3kRpIXvaqCr/+TVmBCiDvvwaMvxlZ+PpUOJMscYtWm8ijouup5AeFqn
QWFzjZjF7ssL7u7Gf28xuWUj8yOJOWpKsMlkgTYz4GuroYsRcbjWOxTbjk9amRiH
fMoQO3EjMBCq3fZUcRfomgc9xhu03Rj/P+sCkFI1kZDQaC5HH6KtnvO5F4INqgQl
OIPuaaYGlaCCqeGoWG/ZAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgEGMB0GA1UdDgQWBBSVDbdkGMKmm2Z22Pz8mlokvCjWzTAfBgNVHSME
GDAWgBSVDbdkGMKmm2Z22Pz8mlokvCjWzTANBgkqhkiG9w0BAQwFAAOCAgEAO8Fc
JcrsEGZXQasT4PtTN1DhvBtABv9iNR8rEeS9k0bTj4Y5FZ2kGeeYHscW3S9fxM37
18nkbCTdGCJX2UM2aw+WZ9pNLjwNUuumxXE8ydnX0TLX7UozULBH7oIoYUJ5a6OF
T/ZfJ4WfET7WXapIYzyl2rQ3VJnjoHLq5u6PqhnU8kJ41tivjsttmlbVJ1LKKMrb
v2JoOv39E4NukarlK/vJ0CDWKGIhziusS/Uj1dxnQ4tYzakMlni3suNcgAl7atMS
hIUP1VjDDfcIs0V8RUfDVXEuyFsCU2FYxTeTwc7NA8V4zqtNKVHgkUoJkDaJM3EM
yscyUf0EibBxMUt/uDLGmcHG/ap3fyNxG8ewtB44ky1DJ6LR6Boq2ieIkhM5TdHr
YldZ39i66Kd7ssFXcUgDzrcQI/wVlCKnjnbhVnsNyB/W6FzdIqYzTzwMC4BYhsiJ
Q9AuEyPDJuetp8Rzdg59zdgiC1zqTMkIWxe5Kdnu/9QzvB12lXyTAS1xGKEWt7XM
3MzhPZjYaB0EHrXdpd79k0YP9gxYIILISa20rWl95IbiYSVR6LvgiZOJV39SyPKH
bRDECL2uz9s0ZgZku0B1yrwUwsL4YW8dNRw7InVzH/EoMANVkhuNQDiF9/zGQX3/
5fcX5tJZaD3vy9mYJAJ5d/vhcGOqHbI3s2W27+c=
-----END CERTIFICATE-----
""",
    ),
    (
        "SK ID Solutions ROOT G1E",
        "a272de102a8038f7e100eacfb6db1c930d3cb9f51d76b218de3a4a433bcfd182",
        """-----BEGIN CERTIFICATE-----
MIICtDCCAhagAwIBAgIQSmaL1ubiC3FhWulCIhJ3+zAKBggqhkjOPQQDBDBmMQsw
CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh
DA5OVFJFRS0xMDc0NzAxMzEhMB8GA1UEAwwYU0sgSUQgU29sdXRpb25zIFJPT1Qg
RzFFMB4XDTIxMTAwNDExNDUwNloXDTQxMTAwNDExNDUwNlowZjELMAkGA1UEBhMC
RUUxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzEXMBUGA1UEYQwOTlRSRUUt
MTA3NDcwMTMxITAfBgNVBAMMGFNLIElEIFNvbHV0aW9ucyBST09UIEcxRTCBmzAQ
BgcqhkjOPQIBBgUrgQQAIwOBhgAEAN+zN0QNRH0pL6ozIEqFSBiqASoVlcgoi2+e
pQ6fU/gJ5ZbySnNtjcfxqqi3sW+XHK3IXN2kwMImzWx/P7S4ZhRfAJNJi6qPmyyD
nXIE17jUuqVBcPZwpap3cqQND3FA3/wgs3r/dnBHyQD4M2ihf3j4IDy/ANl6IiI2
D4Z50ik4QUfYo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAd
BgNVHQ4EFgQUhnRPOus48rCn7u25hZudgwlFMWswHwYDVR0jBBgwFoAUhnRPOus4
8rCn7u25hZudgwlFMWswCgYIKoZIzj0EAwQDgYsAMIGHAkF+pYLDdJjsHc7hvW0d
lIPk6riZKr3PDe6+3t3Paq+Udb4OGw3yzJoxCKQbnLULtlN6weO6wupBn91X+wX6
QbCy/gJCAK/JtP1UsWLkmxCannuKGOIH8CgcKIXdW/z7/TQLfrygdJMgZ5TjzLMH
XoX3gKSTNpCuZEeamEYBzd8HKLDnKYWV
-----END CERTIFICATE-----
""",
    ),
    (
        "EE Certification Centre Root CA",
        "3e84ba4342908516e77573c0992f0979ca084e4685681ff195ccba8a229b8a76",
        """-----BEGIN CERTIFICATE-----
MIIEAzCCAuugAwIBAgIQVID5oHPtPwBMyonY43HmSjANBgkqhkiG9w0BAQUFADB1
MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1
czEoMCYGA1UEAwwfRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYG
CSqGSIb3DQEJARYJcGtpQHNrLmVlMCIYDzIwMTAxMDMwMTAxMDMwWhgPMjAzMDEy
MTcyMzU5NTlaMHUxCzAJBgNVBAYTAkVFMSIwIAYDVQQKDBlBUyBTZXJ0aWZpdHNl
ZXJpbWlza2Vza3VzMSgwJgYDVQQDDB9FRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBS
b290IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDIIMDs4MVLqwd4lfNE7vsLDP90jmG7sWLqI9iroWUy
euuOF0+W2Ap7kaJjbMeMTC55v6kF/GlclY1i+blw7cNRfdCT5mzrMEvhvH2/UpvO
bntl8jixwKIy72KyaOBhU8E2lf/slLo2rpwcpzIP5Xy0xm90/XsY6KxX7QYgSzIw
WFv9zajmofxwvI6Sc9uXp3whrj3B9UiHbCe9nyV0gVWw93X2PaRka9ZP585ArQ/d
MtO8ihJTmMmJ+xAdTX7Nfh9WDSFwhfYggx/2uh8Ej+p3iDXE/+pOoYtNP2MbRMNE
1CV2yreN1x5KZmTNXMWcg+HCCIia7E6j8T4cLNlsHaFLAgMBAAGjgYowgYcwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFBLyWj7qVhy/
zQas8fElyalL1BSZMEUGA1UdJQQ+MDwGCCsGAQUFBwMCBggrBgEFBQcDAQYIKwYB
BQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCAYIKwYBBQUHAwkwDQYJKoZIhvcNAQEF
BQADggEBAHv25MANqhlHt01Xo/6tu7Fq1Q+e2+RjxY6hUFaTlrg4wCQiZrxTFGGV
v9DHKpY5P30osxBAIWrEr7BSdxjhlthWXePdNl4dp1BUoMUq5KqMlIpPnTX/dqQG
E5Gion0ARD9V04I8GtVbvFZMIi5GQ4okQC3zErg7cBqklrkar4dBGmoYDQZPxz5u
uSlNDUmJEYcyW+ZLBMjkXOZ0c5RdFpgTlf7727FE5TpwrDdr5rMzcijJs1eg9gIW
iAYLtqZLICjU3j2LrTcFU3T+bsy8QxdxXvnFzBqpYe73dgzzcvRyrc9yAjYHR8/v
GVCJYMzpJJUPwssd8m92kMfMdcGWxZ0=
-----END CERTIFICATE-----
""",
    ),
)

# Public intermediate CA certificates, shipped only to help build the chain
# offline (sealed PDFs embed just the TSU certificate). They are NOT trust
# anchors: the chain through them must still verify up to a pinned root.
_KNOWN_INTERMEDIATES: Tuple[Tuple[str, str, str], ...] = (
    (
        "SK TSA CA 2023R",
        "cce90c83b505f4bb21ce618ca77e607b8593018b5aa3ee34d7007eb1f2bf11ac",
        """-----BEGIN CERTIFICATE-----
MIIGqTCCBJGgAwIBAgIUUMERb5yfNlE+FJzpVPc4OGi8B7kwDQYJKoZIhvcNAQEM
BQAwZjELMAkGA1UEBhMCRUUxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzEX
MBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxITAfBgNVBAMMGFNLIElEIFNvbHV0aW9u
cyBST09UIEcxUjAeFw0yMzA3MDQwODUzMDJaFw0zODA2MzAwODUzMDFaMF0xGDAW
BgNVBAMMD1NLIFRTQSBDQSAyMDIzUjEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMx
GzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCsjTw6k8cX/jiFXIkoXBbdz/K8aR4o
nSUEtWkCh2lMuT17jtyaVT+KkEJF/pZsKX/n/QpFNouJJd29G73/0JBVLxVR2uXn
trH1fA26SgR1VHz0E5HaxQZcgrEt7yHho9OsNxI52zYKWMtYBhOyZuF/+rgb6B0J
DOGmJsSgIDp89oXNOOY/1i8WxsyP2lEKhYSHW++QShHHHSicAYMU9jwAmaoCZe46
QDYYYLZQMk/xdFfNBgF6HLm4bXqUKK+700VZcjuxHEUkD34OGnq97pL0Kl3tYzOe
Y+U0quTEE1KjNCmV+NAmugRsj70VGzHAU1DxnqeTxyxiBTBycewgERpOASxJrlzp
n5B427QQGlBrWzqh8F0PJpKb6X4KtnErqVR72m+bd6WyoEevFOc94qqcCN56DUHq
4zsh6jUuj53PMS18nmziYPSBC6fN2uP/jcPwrEfo3GM2Sd+s6IHil3vNTEaZ/Xap
G8Mb2Ky6ZWkWaF88VvedTuEiWbrO9matUnvhFC7wh5WqnLWcCmFA7IGEzUx8Mtlj
x4apttfZIZUwqa6op2j6JIPCYgz/MZwk6APVi7rhvy31ZsreeqUPJKREeAnrVsWQ
XW7KzVBMN/UuXJMrpr+dUAF7lWoHTpB5TAEO/boU14LcqaMQEbQeUWtDYQATCVB2
mV//aibDKFjiYwIDAQABo4IBVjCCAVIwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
GDAWgBSVDbdkGMKmm2Z22Pz8mlokvCjWzTBtBggrBgEFBQcBAQRhMF8wOwYIKwYB
BQUHMAKGL2h0dHA6Ly9jLnNrLmVlL1NLX0lEX1NvbHV0aW9uc19ST09UX0cxUi5k
ZXIuY3J0MCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5zay5lZS9DQTBPBgNVHSAE
SDBGMEQGA1UdIDA9MDsGCCsGAQUFBwIBFi9odHRwczovL3d3dy5za2lkc29sdXRp
b25zLmV1L2VuL3JlcG9zaXRvcnkvdHNhLzAvBgNVHR8EKDAmMCSgIqAghh5odHRw
Oi8vYy5zay5lZS9TS19ST09UX0cxUi5jcmwwHQYDVR0OBBYEFP25tFTtuXdg0bHt
JiWEEhVKepIZMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQwFAAOCAgEAlhZJ
UeerY5qr1O49NXaoipWTBvnuVL8GuQL9NGvrCPAkOdp7ZO4OMqeAjJpbvqNuFaHK
+CrXTacfKjnDiixeqAHAsVFI1hDJoZ308YSqgiEGyU6b4TXlAKWa67KO1Lao5Q5l
hwe4vmWTZ+x9zDjLQFAbWNIODSsM1/A4HQEEagRQ8T9wv74xrRMysQ7DBN/0egby
NGXsFI0S6MOUQP1kjC6tNJplj1H6RzKPWs84at8qCptCw7i2ADRdQKNFgLa8Mc6O
axfi4sOmfiirJFFydO5ABLve5p99GBpuy8E4ChSj026WrdeBTtRHtsgFOYCM+ziG
HCeGo+N17Rl9P2u/gEuhv6d1gvGkch3OvZATDOLHYiDg9B5erz4a5nMNE2VoyX1y
ztDAXkDA7vtp3edHqqc9VjoYSSBa8lriBmrw6TMta61KXml0PYfjausqm3yQN1KN
iSOvWlG+1jwf0dAuX+UZev5KiZarBgDH1rd/0q5TDyWRtwczowqFDgjZdj+Cpdo7
JYwGjHEI99OehjhrPjnmhT11RPGIbWzwXDK4ts8gf12awD99cWceC7PC9iNY/abt
5R112kuHTEABXxthQ8JKVX95ONmhLqWKwDwQDm3S9C6MGkXbg2O314zmDC8qAUp1
I0zzUYd7zN5e0dSIow3TuhQZVt9iDVvpiquWA9M=
-----END CERTIFICATE-----
""",
    ),
)

_EXTRA_ROOTS: ContextVar[Tuple[bytes, ...]] = ContextVar("gpa_verify_extra_roots", default=())


def _pem_to_ders(pem: bytes) -> List[bytes]:
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import serialization

    return [c.public_bytes(serialization.Encoding.DER)
            for c in cx509.load_pem_x509_certificates(pem)]


def _load_pinned() -> List[Tuple[str, bytes]]:
    out = []
    for name, fp, pem in _PINNED:
        (der,) = _pem_to_ders(pem.encode("ascii"))
        if hashlib.sha256(der).hexdigest() != fp:  # tamper self-check
            raise RuntimeError(f"pinned root {name}: fingerprint mismatch")
        out.append((name, der))
    return out


def _load_intermediates() -> List[bytes]:
    out = []
    for name, fp, pem in _KNOWN_INTERMEDIATES:
        (der,) = _pem_to_ders(pem.encode("ascii"))
        if hashlib.sha256(der).hexdigest() != fp:
            raise RuntimeError(f"bundled intermediate {name}: fingerprint mismatch")
        out.append(der)
    return out


PINNED_ROOTS: List[Tuple[str, bytes]] = _load_pinned()
KNOWN_INTERMEDIATES: List[bytes] = _load_intermediates()
PINNED_FINGERPRINTS: Dict[str, str] = {fp: name for name, fp, _ in _PINNED}


def load_root_files(paths: Iterable[str]) -> List[bytes]:
    """Read PEM (or DER) root certificates given with --trust-root."""
    ders: List[bytes] = []
    for p in paths:
        with open(p, "rb") as fh:
            raw = fh.read()
        try:
            if b"-----BEGIN" in raw:
                got = _pem_to_ders(raw)
            else:
                from cryptography import x509 as cx509
                from cryptography.hazmat.primitives import serialization
                got = [cx509.load_der_x509_certificate(raw).public_bytes(serialization.Encoding.DER)]
        except Exception as exc:
            raise OSError(f"cannot read certificate from {p}: {exc}") from exc
        if not got:
            raise OSError(f"no certificate in {p}")
        ders.extend(got)
    return ders


def user_roots() -> Tuple[bytes, ...]:
    """Roots added with --trust-root / extra_roots() for the current run."""
    return tuple(_EXTRA_ROOTS.get())


@contextlib.contextmanager
def extra_roots(ders: Iterable[bytes]) -> Iterator[None]:
    """Trust additional root certificates for the duration of the block."""
    tok = _EXTRA_ROOTS.set(tuple(_EXTRA_ROOTS.get()) + tuple(ders))
    try:
        yield
    finally:
        _EXTRA_ROOTS.reset(tok)


def _anchors() -> Dict[str, Tuple[str, bytes, bool]]:
    """sha256(SPKI) -> (label, der, user_supplied). Matching on the public key
    also accepts a re-issued certificate of the same root key."""
    from cryptography import x509 as cx509

    out: Dict[str, Tuple[str, bytes, bool]] = {}
    roots = [(n, d, False) for n, d in PINNED_ROOTS] + [
        (f"user-supplied root ({hashlib.sha256(d).hexdigest()[:16]}…)", d, True)
        for d in _EXTRA_ROOTS.get()
    ]
    for name, der, user in roots:
        c = cx509.load_der_x509_certificate(der)
        out[_spki_sha(c)] = (name, der, user)
    return out


def _tsa_issuer_spkis() -> Dict[str, str]:
    """SPKI hashes of the CAs allowed to issue a TSA certificate directly under
    the pinned SK roots: the SK TSA issuing CA(s), and the roots themselves
    (SK's older TSA certificates were issued directly by EE Certification
    Centre Root CA). SK's personal-ID, Smart-ID and e-seal CAs are NOT here —
    a key certified by them cannot pass as a TSA (review R2)."""
    from cryptography import x509 as cx509

    out = {}
    for (name, _fp, _pem), der in zip(_KNOWN_INTERMEDIATES, KNOWN_INTERMEDIATES):
        out[_spki_sha(cx509.load_der_x509_certificate(der))] = name
    for name, der in PINNED_ROOTS:
        out[_spki_sha(cx509.load_der_x509_certificate(der))] = name
    return out


def _leaf_problem(der: bytes) -> Optional[str]:
    from cryptography import x509 as cx509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    c = cx509.load_der_x509_certificate(der)
    try:
        eku = c.extensions.get_extension_for_class(cx509.ExtendedKeyUsage)
    except cx509.ExtensionNotFound:
        return "TSA certificate has no extendedKeyUsage"
    if not eku.critical or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        return "TSA certificate extendedKeyUsage is not exactly id-kp-timeStamping (critical)"
    try:
        if c.extensions.get_extension_for_class(cx509.BasicConstraints).value.ca:
            return "TSA certificate is a CA certificate"
    except cx509.ExtensionNotFound:
        pass
    return None


def _spki_sha(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def check_trust_root(
    signer_der: Optional[bytes],
    pool_ders: Iterable[bytes],
    at: Optional[datetime],
    *,
    name: str = "tsa_trust_root",
) -> CheckResult:
    """PASS only if the TSA signer certificate chains (every link's signature
    verified, every issuer a CA allowed to sign certificates, every
    certificate valid at ``at``) to a pinned root key; for the pinned SK roots
    the signer must moreover be issued by an SK time-stamping CA and carry
    exactly the critical id-kp-timeStamping EKU."""
    from cryptography import x509 as cx509

    from .tsp_verify import build_chain

    if not signer_der:
        return CheckResult(name=name, passed=False, detail="no TSA signer certificate to check")
    anchors = _anchors()
    # Pinned roots first, so they win over a same-named root shipped in the file.
    pool = [a[1] for a in anchors.values()] + list(pool_ders) + KNOWN_INTERMEDIATES
    try:
        ch = build_chain(signer_der, pool, at)
    except Exception as exc:
        return CheckResult(name=name, passed=False,
                           detail=f"cannot build TSA chain: {type(exc).__name__}: {exc}")
    hit = None
    for i, der in enumerate(ch["ders"]):
        a = anchors.get(_spki_sha(cx509.load_der_x509_certificate(der)))
        if a is not None:
            hit = (i, a[0], a[2])
            break
    extra = {"chain": ch["subjects"], "chain_sha256": ch["sha256"],
             "pinned_roots": sorted(PINNED_FINGERPRINTS.values()),
             "user_roots": len(_EXTRA_ROOTS.get())}
    if hit is None:
        return CheckResult(
            name=name, passed=False,
            detail=("TSA certificate does not chain to a pinned EU QTSP root "
                    f"(chain ends at {ch['subjects'][-1]}); a timestamp from another TSA "
                    "can be accepted with --trust-root <root.pem>"),
            extra=extra)
    # Links up to the anchor must all be valid; errors past it are irrelevant,
    # but build_chain reports validity per certificate, so re-check up to hit.
    bad = [e for e in ch["errors"]
           if any(e.startswith(s) for s in ch["subjects"][: hit[0] + 1])]
    if bad:
        return CheckResult(name=name, passed=False, detail="; ".join(bad), extra=extra)
    leaf_bad = _leaf_problem(ch["ders"][0])
    if leaf_bad:
        return CheckResult(name=name, passed=False, detail=leaf_bad, extra=extra)
    if not hit[2]:  # pinned SK root: the TSA must sit directly under an SK TSA-issuing CA
        if hit[0] == 0 or len(ch["ders"]) < 2:
            return CheckResult(name=name, passed=False,
                               detail="TSA certificate is itself a root certificate", extra=extra)
        issuer_spki = _spki_sha(cx509.load_der_x509_certificate(ch["ders"][1]))
        allowed = _tsa_issuer_spkis()
        if issuer_spki not in allowed:
            return CheckResult(
                name=name, passed=False,
                detail=(f"TSA certificate chains to {hit[1]} but is issued by "
                        f"{ch['subjects'][1]}, which is not an SK time-stamping CA "
                        "(only SK TSA CA 2023R or the root itself may issue TSA certificates)"),
                extra=extra)
        extra["tsa_issuer"] = allowed[issuer_spki]
    extra["trust_root"] = hit[1]
    return CheckResult(
        name=name, passed=True,
        detail=(f"TSA certificate chains to pinned root {hit[1]} "
                f"({hit[0]} link(s), every signature valid at genTime)"),
        extra=extra)
