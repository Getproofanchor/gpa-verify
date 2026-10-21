"""
gpa_verify.qrdecode — minimal pure-Python QR code reader.

Scope is intentionally narrow: it reads QR codes that were *generated
digitally* and embedded as raster images in a PDF (axis-aligned, no
perspective, no blur, crisp modules) — exactly what the GetProofAnchor
Forensic Browser puts on its unsealed "plain copies". It is NOT a camera
scanner.

Steps: binarise → locate the symbol bounding box → derive module size from
the top-left finder pattern → sample a module grid → read format info
(BCH-decoded) → unmask → read codewords in the standard zig-zag order →
de-interleave the Reed-Solomon blocks → verify every block's RS syndromes
(any non-zero syndrome = damaged symbol; we do NOT guess corrections) →
decode numeric / alphanumeric / byte segments (ECI ignored, UTF-8 assumed
for byte mode).

Any failure raises QRError; callers treat that as "QR not readable" and
fall back to other sources. A successful read is exact by construction:
every data and ECC codeword was verified.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple


class QRError(Exception):
    pass


# ISO/IEC 18004 tables (index = version 1..40; index 0 unused).
# Order of error-correction levels: L, M, Q, H.
_ECC_PER_BLOCK = (
    (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
)
_NUM_BLOCKS = (
    (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
    (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
)
# format-info EC bits -> table index (L=01, M=00, Q=11, H=10)
_ECL_FROM_BITS = {1: 0, 0: 1, 3: 2, 2: 3}
_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _raw_data_modules(ver: int) -> int:
    r = (16 * ver + 128) * ver + 64
    if ver >= 2:
        na = ver // 7 + 2
        r -= (25 * na - 10) * na - 55
        if ver >= 7:
            r -= 36
    return r


def _align_positions(ver: int) -> List[int]:
    if ver == 1:
        return []
    size = ver * 4 + 17
    na = ver // 7 + 2
    step = (ver * 8 + na * 3 + 5) // (na * 4 - 4) * 2
    res = [size - 7 - i * step for i in range(na - 1)] + [6]
    return sorted(res)


def _format_codewords() -> List[Tuple[int, int, int]]:
    out = []
    for data in range(32):
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = ((data << 10) | rem) ^ 0x5412
        out.append((bits, data >> 3, data & 7))
    return out


_FORMATS = _format_codewords()


# ── GF(256) for RS syndrome check ─────────────────────────────────────────────
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _rs_ok(block: Sequence[int], necc: int) -> bool:
    for i in range(necc):
        s = 0
        a = _EXP[i]
        for c in block:
            # Horner: s = s*a + c
            s = (_EXP[_LOG[s] + _LOG[a]] if s else 0) ^ c
        if s:
            return False
    return True


# ── image → module grid ──────────────────────────────────────────────────────

def _binarize(width: int, height: int, channels: int, pixels: bytes) -> List[List[bool]]:
    lum = []
    if channels == 1:
        lum = list(pixels[: width * height])
    else:
        for i in range(0, width * height * channels, channels):
            r, g, b = pixels[i], pixels[i + 1], pixels[i + 2]
            lum.append((r * 299 + g * 587 + b * 114) // 1000)
    lo, hi = min(lum), max(lum)
    if hi - lo < 64:
        raise QRError("image has too little contrast")
    thr = (lo + hi) // 2
    return [[lum[y * width + x] < thr for x in range(width)] for y in range(height)]


def _sample_grid(dark: List[List[bool]]) -> List[List[bool]]:
    h = len(dark)
    w = len(dark[0]) if h else 0
    rows = [y for y in range(h) if any(dark[y])]
    cols = [x for x in range(w) if any(dark[y][x] for y in range(h))]
    if not rows or not cols:
        raise QRError("blank image")
    top, bottom, left, right = rows[0], rows[-1], cols[0], cols[-1]
    # Finder pattern on the top row of the symbol: 7 dark modules wide.
    x = left
    while x <= right and dark[top][x]:
        x += 1
    finder_w = x - left
    if finder_w <= 0:
        raise QRError("no finder pattern")
    mod = finder_w / 7.0
    span_w = right - left + 1
    span_h = bottom - top + 1
    n = round(span_w / mod)
    ver = round((n - 17) / 4)
    if ver < 1 or ver > 40:
        raise QRError(f"implausible symbol size {n}")
    n = ver * 4 + 17
    mod_x = span_w / n
    mod_y = span_h / n
    if abs(mod_x - mod_y) > 0.25 * max(mod_x, mod_y):
        raise QRError("symbol is not square")
    grid = []
    for r in range(n):
        yy = int(top + (r + 0.5) * mod_y)
        row = []
        for c in range(n):
            xx = int(left + (c + 0.5) * mod_x)
            row.append(dark[min(yy, h - 1)][min(xx, w - 1)])
        grid.append(row)
    # sanity: the three finder patterns' centres must be dark
    for (cy, cx) in ((3, 3), (3, n - 4), (n - 4, 3)):
        if not grid[cy][cx]:
            raise QRError("finder pattern check failed")
    return grid


# ── decoding ─────────────────────────────────────────────────────────────────

def _function_map(ver: int) -> List[List[bool]]:
    n = ver * 4 + 17
    f = [[False] * n for _ in range(n)]

    def mark(r0, c0, hh, ww):
        for r in range(max(0, r0), min(n, r0 + hh)):
            for c in range(max(0, c0), min(n, c0 + ww)):
                f[r][c] = True

    mark(0, 0, 9, 9)
    mark(0, n - 8, 9, 8)
    mark(n - 8, 0, 8, 9)
    for i in range(n):
        f[6][i] = True
        f[i][6] = True
    al = _align_positions(ver)
    for i, a in enumerate(al):
        for j, b in enumerate(al):
            if (i == 0 and j == 0) or (i == 0 and j == len(al) - 1) or (i == len(al) - 1 and j == 0):
                continue
            mark(a - 2, b - 2, 5, 5)
    if ver >= 7:
        mark(0, n - 11, 6, 3)
        mark(n - 11, 0, 3, 6)
    return f


def _read_format(grid: List[List[bool]]) -> Tuple[int, int]:
    n = len(grid)

    def m(x, y):  # x = column, y = row
        return 1 if grid[y][x] else 0

    a = 0
    for i in range(6):
        a |= m(8, i) << i
    a |= m(8, 7) << 6
    a |= m(8, 8) << 7
    a |= m(7, 8) << 8
    for i in range(9, 15):
        a |= m(14 - i, 8) << i
    b = 0
    for i in range(8):
        b |= m(n - 1 - i, 8) << i
    for i in range(8, 15):
        b |= m(8, n - 15 + i) << i
    best = None
    for bits, ecb, mask in _FORMATS:
        for cand in (a, b):
            d = bin(bits ^ cand).count("1")
            if best is None or d < best[0]:
                best = (d, ecb, mask)
    if best is None or best[0] > 3:
        raise QRError("format information unreadable")
    return _ECL_FROM_BITS[best[1]], best[2]


def _mask_bit(mask: int, x: int, y: int) -> bool:
    if mask == 0:
        return (x + y) % 2 == 0
    if mask == 1:
        return y % 2 == 0
    if mask == 2:
        return x % 3 == 0
    if mask == 3:
        return (x + y) % 3 == 0
    if mask == 4:
        return (x // 3 + y // 2) % 2 == 0
    if mask == 5:
        return x * y % 2 + x * y % 3 == 0
    if mask == 6:
        return (x * y % 2 + x * y % 3) % 2 == 0
    return ((x + y) % 2 + x * y % 3) % 2 == 0


def _read_codewords(grid: List[List[bool]], ver: int, mask: int) -> List[int]:
    n = len(grid)
    func = _function_map(ver)
    nbits = _raw_data_modules(ver) // 8 * 8
    bits: List[int] = []
    right = n - 1
    while right >= 1 and len(bits) < nbits:
        if right == 6:
            right = 5
        for vert in range(n):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = (n - 1 - vert) if upward else vert
                if not func[y][x] and len(bits) < nbits:
                    v = grid[y][x] ^ _mask_bit(mask, x, y)
                    bits.append(1 if v else 0)
        right -= 2
    out = []
    for i in range(0, len(bits), 8):
        b = 0
        for k in range(8):
            b = (b << 1) | bits[i + k]
        out.append(b)
    return out


def _deinterleave(cw: List[int], ver: int, ecl: int) -> List[int]:
    nblocks = _NUM_BLOCKS[ecl][ver]
    necc = _ECC_PER_BLOCK[ecl][ver]
    raw = _raw_data_modules(ver) // 8
    nshort = nblocks - raw % nblocks
    short_len = raw // nblocks
    blocks: List[List[int]] = [[] for _ in range(nblocks)]
    k = 0
    for i in range(short_len - necc + 1):
        for b in range(nblocks):
            if i == short_len - necc and b < nshort:
                continue
            blocks[b].append(cw[k])
            k += 1
    for i in range(necc):
        for b in range(nblocks):
            blocks[b].append(cw[k])
            k += 1
    data: List[int] = []
    for b in blocks:
        if not _rs_ok(b, necc):
            raise QRError("Reed-Solomon check failed (damaged symbol)")
        data.extend(b[:-necc])
    return data


def _decode_segments(data: List[int], ver: int) -> bytes:
    bits = "".join(f"{b:08b}" for b in data)
    p = 0
    out = bytearray()
    grp = 0 if ver <= 9 else (1 if ver <= 26 else 2)

    def take(k: int) -> int:
        nonlocal p
        if p + k > len(bits):
            raise QRError("truncated bit stream")
        v = int(bits[p:p + k], 2)
        p += k
        return v

    while p + 4 <= len(bits):
        mode = take(4)
        if mode == 0:
            break
        if mode == 7:  # ECI
            first = take(8)
            if first & 0x80:
                take(8 if (first & 0xC0) == 0x80 else 16)
            continue
        if mode == 4:
            cnt = take((8, 16, 16)[grp])
            for _ in range(cnt):
                out.append(take(8))
        elif mode == 2:
            cnt = take((9, 11, 13)[grp])
            while cnt >= 2:
                v = take(11)
                out.extend((_ALNUM[v // 45] + _ALNUM[v % 45]).encode())
                cnt -= 2
            if cnt:
                out.extend(_ALNUM[take(6)].encode())
        elif mode == 1:
            cnt = take((10, 12, 14)[grp])
            while cnt >= 3:
                out.extend(f"{take(10):03d}".encode())
                cnt -= 3
            if cnt == 2:
                out.extend(f"{take(7):02d}".encode())
            elif cnt == 1:
                out.extend(f"{take(4):d}".encode())
        else:
            raise QRError(f"unsupported QR segment mode {mode}")
    return bytes(out)


def decode_grid(grid: List[List[bool]]) -> bytes:
    n = len(grid)
    ver = (n - 17) // 4
    ecl, mask = _read_format(grid)
    cw = _read_codewords(grid, ver, mask)
    data = _deinterleave(cw, ver, ecl)
    return _decode_segments(data, ver)


def decode_image(width: int, height: int, channels: int, pixels: bytes,
                 invert: Optional[bool] = None) -> bytes:
    """Decode one QR symbol from raw 8-bit Gray/RGB pixels. Raises QRError."""
    if width < 21 or height < 21:
        raise QRError("image too small")
    dark = _binarize(width, height, channels, pixels)
    grid = _sample_grid(dark)
    return decode_grid(grid)
