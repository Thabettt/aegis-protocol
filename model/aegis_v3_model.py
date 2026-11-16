#!/usr/bin/env python3
"""
Aegis v3 -- executable model
============================

A dependency-free model of Aegis_project_specification.md v3.0 (sections 3-11).
Standard library only. Python 3.9+.

    python aegis_v3_model.py            self-test, run all checks, write vectors
    python aegis_v3_model.py --check    same, but do not write the vectors file

What this is for
    * showing the specification can be implemented exactly as written;
    * producing known-answer and negative test vectors;
    * serving as a differential-testing oracle for the reference implementation.

What this is NOT
    * It is not constant-time, not fast, and must never handle real secrets.
    * Its functions take LS, KS and other secrets as parameters so vectors are
      reproducible. A real implementation MUST NOT expose such an interface
      (spec 4.4 rule 1).
    * X-Wing and Argon2id are not implemented here. Where a vector needs their
      outputs, the values are supplied as inputs and marked "injected".
    * The vectors are PROVISIONAL until an independent implementation
      reproduces them (implementation plan, milestone M4).
"""

import hashlib
import hmac
import json
import os
import re
import struct
import sys

PROTO = b"AEGIS-v3"
VERSION = 0x03
CHUNK = 65536
TAG = 16
ENC_CHUNK = CHUNK + TAG
OH_LEN = 1168
HDR_LEN = 1200
HP_LEN = 1152
KEM_CT_LEN = 1120
KEM_PK_LEN = 1216
MAX_MLEN = 16384
MAX_CARD_WINDOW = 7_776_000

F_SPLIT, F_LIVE = 0x01, 0x02
H_ADDRESSED, H_PASSPHRASE, H_SIGNED = 0x01, 0x02, 0x04
EXT_NOTE, EXT_BURN = 0x0001, 0x0002


class AegisError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def u8(n):
    return struct.pack(">B", n)


def u16(n):
    return struct.pack(">H", n)


def u32(n):
    return struct.pack(">I", n)


def u64(n):
    return struct.pack(">Q", n)


def u88(n):
    return n.to_bytes(11, "big")


def ct_eq(a, b):
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------
# Primitives (spec 3.1)
# --------------------------------------------------------------------------

def sha512(b):
    return hashlib.sha512(b).digest()


def hkdf_extract(salt, ikm, h="sha512"):
    if not salt:
        salt = bytes(hashlib.new(h).digest_size)
    return hmac.new(salt, ikm, h).digest()


def hkdf_expand(prk, info, length, h="sha512"):
    hl = hashlib.new(h).digest_size
    assert 0 < length <= 255 * hl
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
        i += 1
    return okm[:length]


# ChaCha20-Poly1305, RFC 8439 ------------------------------------------------

_M32 = 0xFFFFFFFF


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _M32
    s[d] ^= s[a]
    s[d] = ((s[d] << 16) & _M32) | (s[d] >> 16)
    s[c] = (s[c] + s[d]) & _M32
    s[b] ^= s[c]
    s[b] = ((s[b] << 12) & _M32) | (s[b] >> 20)
    s[a] = (s[a] + s[b]) & _M32
    s[d] ^= s[a]
    s[d] = ((s[d] << 8) & _M32) | (s[d] >> 24)
    s[c] = (s[c] + s[d]) & _M32
    s[b] ^= s[c]
    s[b] = ((s[b] << 7) & _M32) | (s[b] >> 25)


def chacha20_block(key, counter, nonce):
    init = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    init += list(struct.unpack("<8I", key))
    init += [counter & _M32]
    init += list(struct.unpack("<3I", nonce))
    s = init[:]
    for _ in range(10):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)
    return struct.pack("<16I", *[(s[i] + init[i]) & _M32 for i in range(16)])


def chacha20_xor(key, counter, nonce, data):
    if not data:
        return b""
    blocks = -(-len(data) // 64)
    ks = b"".join(chacha20_block(key, counter + i, nonce) for i in range(blocks))
    x = int.from_bytes(data, "little") ^ int.from_bytes(ks[: len(data)], "little")
    return x.to_bytes(len(data), "little")


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i : i + 16]
        acc = (acc + int.from_bytes(blk, "little") + (1 << (8 * len(blk)))) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(x):
    return bytes(-len(x) % 16)


def _aead_mac(key, nonce, aad, ct):
    otk = chacha20_block(key, 0, nonce)[:32]
    data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return poly1305(otk, data)


def aead_seal(key, nonce, aad, pt):
    assert len(key) == 32 and len(nonce) == 12
    ct = chacha20_xor(key, 1, nonce, pt)
    return ct + _aead_mac(key, nonce, aad, ct)


def aead_open(key, nonce, aad, boxed):
    """Returns plaintext, or None if authentication fails."""
    assert len(key) == 32 and len(nonce) == 12
    if len(boxed) < TAG:
        return None
    ct, tag = boxed[:-TAG], boxed[-TAG:]
    if not ct_eq(tag, _aead_mac(key, nonce, aad, ct)):
        return None
    return chacha20_xor(key, 1, nonce, ct)


# Ed25519, RFC 8032, with strict verification (spec 3.3) ---------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENT = (0, 1, 1, 0)


def _pt_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    Dd = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pt_mul(s, pt):
    q = _IDENT
    while s > 0:
        if s & 1:
            q = _pt_add(q, pt)
        pt = _pt_add(pt, pt)
        s >>= 1
    return q


def _pt_eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None  # non-canonical y
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0  # x = 0 with sign bit set is non-canonical
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _pt_compress(pt):
    zi = pow(pt[2], _P - 2, _P)
    x, y = pt[0] * zi % _P, pt[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _pt_decompress(s):
    """Rejects non-canonical encodings."""
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _ed_expand(seed):
    h = sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed_public(seed):
    a, _ = _ed_expand(seed)
    return _pt_compress(_pt_mul(a, _G))


def ed_sign(seed, msg):
    a, prefix = _ed_expand(seed)
    A = _pt_compress(_pt_mul(a, _G))
    r = int.from_bytes(sha512(prefix + msg), "little") % _L
    R = _pt_compress(_pt_mul(r, _G))
    k = int.from_bytes(sha512(R + A + msg), "little") % _L
    return R + ((r + k * a) % _L).to_bytes(32, "little")


def _small_order(pt):
    return _pt_eq(_pt_mul(8, pt), _IDENT)


def ed_verify_strict(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    A = _pt_decompress(pub)
    R = _pt_decompress(sig[:32])
    if A is None or R is None:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    if _small_order(A) or _small_order(R):
        return False
    k = int.from_bytes(sha512(sig[:32] + pub + msg), "little") % _L
    return _pt_eq(_pt_mul(S, _G), _pt_add(R, _pt_mul(k, A)))


# X25519, RFC 7748 (used only by the live handshake) -------------------------

_X_BASE = (9).to_bytes(32, "little")


def x25519(k, u):
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    kn = int.from_bytes(kb, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (kn >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = (x2 + z2) % _P
        AA = A * A % _P
        B = (x2 - z2) % _P
        BB = B * B % _P
        E = (AA - BB) % _P
        C = (x3 + z3) % _P
        Dd = (x3 - z3) % _P
        DA = Dd * A % _P
        CB = C * B % _P
        x3 = (DA + CB) ** 2 % _P
        z3 = x1 * (DA - CB) ** 2 % _P
        x2 = AA * BB % _P
        z2 = E * (AA + 121665 * E) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


# --------------------------------------------------------------------------
# Labelled derivation (spec 3.2)
# --------------------------------------------------------------------------

def ctx(label):
    lb = label.encode("ascii")
    assert 1 <= len(lb) <= 255
    return PROTO + u8(len(lb)) + lb


def lextract(salt, label, ikm):
    return hkdf_extract(salt, ctx(label) + ikm)


def lexpand(prk, label, info, length):
    return hkdf_expand(prk, u16(length) + ctx(label) + info, length)


def lhash(label, data):
    return sha512(ctx(label) + data)


def lsign(seed, label, data):
    return ed_sign(seed, ctx(label) + data)


def lverify(pub, label, data, sig):
    return ed_verify_strict(pub, ctx(label) + data, sig)


# --------------------------------------------------------------------------
# Text encoding (spec 4.3)
# --------------------------------------------------------------------------

_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def b32enc(data):
    nbits = len(data) * 8
    pad = -nbits % 5
    v = int.from_bytes(data, "big") << pad
    n = (nbits + pad) // 5
    return "".join(_B32[(v >> (5 * (n - 1 - i))) & 31] for i in range(n))


def b32dec(text):
    s = text.replace(" ", "").replace("-", "").lower()
    if not s or any(c not in _B32 for c in s):
        raise AegisError("AEG-FMT-01", "invalid base32 character")
    v = 0
    for c in s:
        v = (v << 5) | _B32.index(c)
    extra = len(s) * 5 % 8
    if extra >= 5 or v & ((1 << extra) - 1):
        raise AegisError("AEG-FMT-01", "non-canonical base32")
    return (v >> extra).to_bytes(len(s) * 5 // 8, "big")


# --------------------------------------------------------------------------
# Artifacts (spec 4.1, 4.2)
# --------------------------------------------------------------------------

_ORIGIN_RE = re.compile(
    r"^(https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?|http://[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.onion)(:[0-9]{1,5})?$"
)


def encode_link(LS, origin, split, live=False):
    ob = origin.encode("ascii")
    assert len(LS) == 32 and 1 <= len(ob) <= 255 and _ORIGIN_RE.match(origin)
    body = u8(VERSION) + u8((F_SPLIT if split else 0) | (F_LIVE if live else 0)) + LS + u8(len(ob)) + ob
    return "aegis:link:" + b32enc(body + lhash("link check", body)[:4])


def decode_link(text):
    if not text.lower().startswith("aegis:link:"):
        raise AegisError("AEG-FMT-01", "not a ShareLink")
    raw = b32dec(text[11:])
    if len(raw) < 40:
        raise AegisError("AEG-FMT-01", "ShareLink too short")
    if raw[0] != VERSION:
        raise AegisError("AEG-FMT-02", "unsupported version")
    if not ct_eq(raw[-4:], lhash("link check", raw[:-4])[:4]):
        raise AegisError("AEG-FMT-01", "ShareLink checksum")
    lflags, LS, olen = raw[1], raw[2:34], raw[34]
    if lflags & ~(F_SPLIT | F_LIVE):
        raise AegisError("AEG-FMT-01", "reserved lflags bit")
    if olen < 1 or len(raw) != 35 + olen + 4:
        raise AegisError("AEG-FMT-01", "ShareLink length")
    try:
        origin = raw[35 : 35 + olen].decode("ascii")
    except UnicodeDecodeError:
        raise AegisError("AEG-FMT-01", "origin not ASCII")
    if not _ORIGIN_RE.match(origin):
        raise AegisError("AEG-FMT-01", "origin syntax")
    return {"LS": LS, "split": bool(lflags & F_SPLIT), "live": bool(lflags & F_LIVE), "origin": origin}


def encode_key(KS):
    assert len(KS) == 32
    body = u8(VERSION) + KS
    return "aegis:key:" + b32enc(body + lhash("key check", body)[:4])


def decode_key(text):
    if not text.lower().startswith("aegis:key:"):
        raise AegisError("AEG-FMT-01", "not a ShareKey")
    raw = b32dec(text[10:])
    if len(raw) != 37:
        raise AegisError("AEG-FMT-01", "ShareKey length")
    if raw[0] != VERSION:
        raise AegisError("AEG-FMT-02", "unsupported version")
    if not ct_eq(raw[-4:], lhash("key check", raw[:-4])[:4]):
        raise AegisError("AEG-FMT-01", "ShareKey checksum")
    return raw[1:33]


# --------------------------------------------------------------------------
# Key schedule (spec 6)
# --------------------------------------------------------------------------

def stage_a(LS, KS):
    """KS is None when SPLIT is not set."""
    mode = 0x01 if KS is not None else 0x00
    ikm = u8(mode) + LS + (KS if KS is not None else b"")
    prk = lextract(b"", "artifact", ikm)
    return {
        "mode": mode,
        "PRK_A": prk,
        "blob_id": lexpand(prk, "blob id", b"", 32),
        "K_hdr": lexpand(prk, "header key", b"", 32),
        "T_burn": lexpand(prk, "burn token", b"", 32),
        "live_id": lexpand(prk, "live id", b"", 32),
        "live_psk": lexpand(prk, "live psk", b"", 32),
        "chain": lexpand(prk, "chain", b"", 64),
    }


def build_hp(hflags, pw_profile=0, pw_salt=bytes(16), kem_ct=bytes(KEM_CT_LEN)):
    hp = u8(hflags) + u8(pw_profile) + bytes(14) + pw_salt + kem_ct
    assert len(hp) == HP_LEN
    return hp


def seal_header(a, hp):
    return aead_seal(a["K_hdr"], bytes(12), ctx("header") + a["blob_id"], hp)


def parse_hp(hp):
    """Strict parse (spec 6.2)."""
    hflags, prof = hp[0], hp[1]
    pw_salt, kem_ct = hp[16:32], hp[32:]
    bad = AegisError("AEG-FMT-03", "non-canonical header")
    if hflags & ~(H_ADDRESSED | H_PASSPHRASE | H_SIGNED) or any(hp[2:16]):
        raise bad
    if hflags & H_PASSPHRASE:
        if prof not in (0x01, 0x02):
            raise bad
    elif prof != 0 or any(pw_salt):
        raise bad
    if not hflags & H_ADDRESSED and any(kem_ct):
        raise bad
    return {
        "addressed": bool(hflags & H_ADDRESSED),
        "passphrase": bool(hflags & H_PASSPHRASE),
        "signed": bool(hflags & H_SIGNED),
        "pw_profile": prof,
        "pw_salt": pw_salt,
        "kem_ct": kem_ct,
    }


def recipient_binding(ik_pub, kem_pub):
    return lhash("recipient", ik_pub + kem_pub)


def transcript(a, oh, rcpt):
    assert len(oh) == OH_LEN and len(rcpt) == 64
    return lhash("transcript", u8(a["mode"]) + a["blob_id"] + oh + rcpt)


def stage_b(a, th, ss_kem=bytes(32), pw_key=bytes(32)):
    prk = lextract(b"", "root", a["chain"] + ss_kem + pw_key)
    return {
        "PRK_B": prk,
        "commit": lexpand(prk, "commit", th, 32),
        "K_payload": lexpand(prk, "payload key", th, 32),
    }


# --------------------------------------------------------------------------
# Blob (spec 7)
# --------------------------------------------------------------------------

def padme(length):
    assert length >= 2
    e = length.bit_length() - 1
    s = e.bit_length()  # floor(log2(e)) + 1
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask


def build_manifest(content_len, name, media_type, sender_ik=bytes(32), exts=()):
    nb, tb = name.encode("utf-8"), media_type.encode("ascii")
    body = u64(content_len) + sender_ik + u16(len(nb)) + nb + u8(len(tb)) + tb
    for t, v in exts:
        body += u16(t) + u16(len(v)) + v
    return u32(len(body)) + body


def parse_manifest(P, signed):
    bad = lambda why: AegisError("AEG-FMT-04", why)
    if len(P) < 4:
        raise bad("no manifest")
    mlen = struct.unpack(">I", P[:4])[0]
    if not 43 <= mlen <= MAX_MLEN or 4 + mlen > len(P):
        raise bad("mlen")
    body = P[4 : 4 + mlen]
    content_len = struct.unpack(">Q", body[:8])[0]
    sender_ik = body[8:40]
    if any(sender_ik) != signed:
        raise bad("sender_ik inconsistent with SIGNED")
    off = 40
    name_len = struct.unpack(">H", body[off : off + 2])[0]
    off += 2
    if name_len > 1024 or off + name_len + 1 > mlen:
        raise bad("name_len")
    try:
        name = body[off : off + name_len].decode("utf-8")
    except UnicodeDecodeError:
        raise bad("name not UTF-8")
    if "\x00" in name:
        raise bad("NUL in name")
    off += name_len
    type_len = body[off]
    off += 1
    if type_len > 127 or off + type_len > mlen:
        raise bad("type_len")
    mt = body[off : off + type_len]
    if any(not 0x21 <= c <= 0x7E for c in mt):
        raise bad("media_type bytes")
    off += type_len
    exts, prev = {}, -1
    while off < mlen:
        if off + 4 > mlen:
            raise bad("truncated extension")
        t, ln = struct.unpack(">HH", body[off : off + 4])
        off += 4
        if off + ln > mlen:
            raise bad("extension length")
        if t <= prev:
            raise bad("extensions not strictly ascending")
        prev = t
        val = body[off : off + ln]
        off += ln
        if t == EXT_NOTE:
            if ln > 4096:
                raise bad("note too long")
            try:
                exts["note"] = val.decode("utf-8")
            except UnicodeDecodeError:
                raise bad("note not UTF-8")
        elif t == EXT_BURN:
            if ln != 0:
                raise bad("burn must be empty")
            exts["burn"] = True
        elif t & 0x8000:
            raise bad("unknown critical extension")
    return {
        "mlen": mlen,
        "content_len": content_len,
        "sender_ik": sender_ik,
        "name": name,
        "media_type": mt.decode("ascii"),
        **exts,
    }


def encrypt_stream(k_payload, P):
    assert len(P) >= 1
    n = -(-len(P) // CHUNK)
    out = []
    for i in range(n):
        last = 1 if i == n - 1 else 0
        out.append(aead_seal(k_payload, u88(i) + u8(last), b"", P[i * CHUNK : (i + 1) * CHUNK]))
    return b"".join(out)


def split_chunks(blob):
    body = len(blob) - HDR_LEN
    if body < TAG + 1:
        raise AegisError("AEG-FMT-03", "blob too short")
    n = -(-body // ENC_CHUNK)
    tail = body - (n - 1) * ENC_CHUNK
    if not TAG + 1 <= tail <= ENC_CHUNK:
        raise AegisError("AEG-FMT-03", "impossible blob length")
    return [blob[HDR_LEN + i * ENC_CHUNK : HDR_LEN + (i + 1) * ENC_CHUNK] for i in range(n)]


def sender_sig_message(th, commit, p_unsigned):
    return th + commit + lhash("stream digest", p_unsigned)


# --------------------------------------------------------------------------
# Procedures (spec 8)
# --------------------------------------------------------------------------

def derive(LS, KS, hp, rcpt=bytes(64), ss_kem=bytes(32), pw_key=bytes(32)):
    a = stage_a(LS, KS)
    oh = seal_header(a, hp)
    th = transcript(a, oh, rcpt)
    b = stage_b(a, th, ss_kem, pw_key)
    return a, oh, th, b


def assemble(oh, b, P):
    """Lowest-level blob construction. Also used to craft malformed blobs."""
    return oh + b["commit"] + encrypt_stream(b["K_payload"], P)


def seal(content, name, media_type, *, LS, KS=None, origin, live=False,
         addressed=None, passphrase=None, signer_seed=None, note=None, burn=False):
    """
    addressed  = {"ik_pub", "kem_pub", "kem_ct", "ss_kem"}   (KEM outputs injected)
    passphrase = {"pw_profile", "pw_salt", "pw_key"}         (Argon2id output injected)
    """
    hflags, rcpt, ss_kem, pw_key = 0, bytes(64), bytes(32), bytes(32)
    kw = {}
    if addressed:
        hflags |= H_ADDRESSED
        kw["kem_ct"] = addressed["kem_ct"]
        ss_kem = addressed["ss_kem"]
        rcpt = recipient_binding(addressed["ik_pub"], addressed["kem_pub"])
    if passphrase:
        hflags |= H_PASSPHRASE
        kw["pw_profile"], kw["pw_salt"] = passphrase["pw_profile"], passphrase["pw_salt"]
        pw_key = passphrase["pw_key"]
    if signer_seed:
        hflags |= H_SIGNED
    hp = build_hp(hflags, **kw)
    a, oh, th, b = derive(LS, KS, hp, rcpt, ss_kem, pw_key)

    exts = []
    if note is not None:
        exts.append((EXT_NOTE, note.encode("utf-8")))
    if burn:
        exts.append((EXT_BURN, b""))
    sender_ik = ed_public(signer_seed) if signer_seed else bytes(32)
    manifest = build_manifest(len(content), name, media_type, sender_ik, exts)
    siglen = 64 if signer_seed else 0
    n = len(manifest) + len(content) + siglen
    plen = padme(max(n, CHUNK))
    P = manifest + content + bytes(plen - n)
    if signer_seed:
        P += lsign(signer_seed, "sender signature", sender_sig_message(th, b["commit"], P))
    assert len(P) == plen
    return {
        "blob": assemble(oh, b, P),
        "link": encode_link(LS, origin, KS is not None, live),
        "key": encode_key(KS) if KS is not None else None,
        "a": a, "hp": hp, "oh": oh, "rcpt": rcpt, "th": th, "b": b,
        "manifest": manifest, "n": n, "P": P,
    }


def open_blob(link, key, blob, *, kem_candidates=(), pw_key=None):
    """
    kem_candidates = [(ik_pub, kem_pub, ss_kem)], newest first. ss_kem stands in
    for XWing.Decaps(sk, kem_ct). pw_key stands in for Argon2id(passphrase, pw_salt).
    """
    lk = decode_link(link)
    if lk["split"] and key is None:
        raise AegisError("AEG-FMT-01", "ShareKey required")
    KS = decode_key(key) if lk["split"] else None
    a = stage_a(lk["LS"], KS)

    chunks = split_chunks(blob)
    oh, commit = blob[:OH_LEN], blob[OH_LEN:HDR_LEN]
    hp = aead_open(a["K_hdr"], bytes(12), ctx("header") + a["blob_id"], oh)
    if hp is None:
        raise AegisError("AEG-CRYPTO-01", "header authentication")
    h = parse_hp(hp)

    pk = bytes(32)
    if h["passphrase"]:
        if pw_key is None:
            raise AegisError("AEG-CRYPTO-02", "passphrase required")
        pk = pw_key
    cands = ([(recipient_binding(i, k), s) for i, k, s in kem_candidates]
             if h["addressed"] else [(bytes(64), bytes(32))])
    sel = None
    for rcpt, ss in cands:
        th = transcript(a, oh, rcpt)
        b = stage_b(a, th, ss, pk)
        if ct_eq(b["commit"], commit):
            sel = (th, b)
            break
    if sel is None:
        raise AegisError("AEG-CRYPTO-02", "commitment mismatch")
    th, b = sel

    # Release rule (spec 8.3): nothing below is returned unless every check passes.
    parts = []
    for i, c in enumerate(chunks):
        last = 1 if i == len(chunks) - 1 else 0
        pt = aead_open(b["K_payload"], u88(i) + u8(last), b"", c)
        if pt is None:
            raise AegisError("AEG-CRYPTO-03", f"chunk {i}")
        parts.append(pt)
    P = b"".join(parts)

    m = parse_manifest(P, h["signed"])
    siglen = 64 if h["signed"] else 0
    n = 4 + m["mlen"] + m["content_len"] + siglen
    if n > len(P) or len(P) != padme(max(n, CHUNK)):
        raise AegisError("AEG-FMT-04", "length is not the canonical padded length")
    c0 = 4 + m["mlen"]
    content = P[c0 : c0 + m["content_len"]]
    if any(P[c0 + m["content_len"] : len(P) - siglen]):
        raise AegisError("AEG-FMT-04", "non-zero padding")
    signer = None
    if h["signed"]:
        msg = sender_sig_message(th, commit, P[:-64])
        if not lverify(m["sender_ik"], "sender signature", msg, P[-64:]):
            raise AegisError("AEG-AUTH-01", "sender signature")
        signer = m["sender_ik"]
    return {
        "content": content, "name": m["name"], "media_type": m["media_type"],
        "note": m.get("note"), "burn": m.get("burn", False), "signer": signer,
        "blob_id": a["blob_id"],
    }


# --------------------------------------------------------------------------
# Identity (spec 9)
# --------------------------------------------------------------------------

def identity_from_seed(seed):
    prk = lextract(b"", "identity root", seed)
    ik_seed = lexpand(prk, "identity key", b"", 32)
    return ik_seed, ed_public(ik_seed)


def fingerprint(ik_pub):
    f = b32enc(lhash("fingerprint", ik_pub)[:20])
    return " ".join(f[i : i + 4] for i in range(0, 32, 4))


def make_card(ik_seed, kem_pub, not_before, not_after):
    assert len(kem_pub) == KEM_PK_LEN
    body = u8(VERSION) + ed_public(ik_seed) + kem_pub + u64(not_before) + u64(not_after)
    signed = body + lsign(ik_seed, "card", body)
    return signed + lhash("card check", signed)[:4]


def validate_card(card, now):
    """Checks 1-4 of spec 9.4. The ML-KEM key check (5) and contact check (6) are not modelled."""
    bad = lambda why: AegisError("AEG-AUTH-02", why)
    if len(card) != 1333:
        raise bad("length")
    if card[0] != VERSION:
        raise AegisError("AEG-FMT-02", "unsupported version")
    if not ct_eq(card[-4:], lhash("card check", card[:-4])[:4]):
        raise bad("checksum")
    ik_pub, kem_pub = card[1:33], card[33:1249]
    nb, na = struct.unpack(">QQ", card[1249:1265])
    if not lverify(ik_pub, "card", card[:1265], card[1265:1329]):
        raise bad("signature")
    if not nb < na or na - nb > MAX_CARD_WINDOW:
        raise bad("validity window")
    if now >= na:
        raise bad("expired")
    return {"ik_pub": ik_pub, "kem_pub": kem_pub, "not_before": nb, "not_after": na}


# --------------------------------------------------------------------------
# Storage service helpers (spec 10.3, 10.4)
# --------------------------------------------------------------------------

def verifier(token):
    return lhash("delete verifier", token)[:32]


def _lz_bits(b):
    v = int.from_bytes(b, "big")
    return len(b) * 8 - v.bit_length()


def pow_valid(challenge, ident, counter, bits):
    return _lz_bits(lhash("pow", challenge + ident + u64(counter))) >= bits


def pow_solve(challenge, ident, bits):
    c = 0
    while not pow_valid(challenge, ident, c, bits):
        c += 1
    return c


# --------------------------------------------------------------------------
# Live handshake (spec 11.3): Noise_NNpsk0_25519_ChaChaPoly_SHA512
# --------------------------------------------------------------------------

NOISE_NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA512"


class _Sym:
    def __init__(self, prologue):
        self.h = NOISE_NAME + bytes(64 - len(NOISE_NAME))
        self.ck, self.k, self.n = self.h, None, 0
        self.mix_hash(prologue)

    def mix_hash(self, d):
        self.h = sha512(self.h + d)

    def _hkdf(self, ikm, outs):
        tk = hmac.new(self.ck, ikm, "sha512").digest()
        o = [hmac.new(tk, b"\x01", "sha512").digest()]
        for i in range(2, outs + 1):
            o.append(hmac.new(tk, o[-1] + bytes([i]), "sha512").digest())
        return o

    def mix_key(self, ikm):
        self.ck, tk = self._hkdf(ikm, 2)
        self.k, self.n = tk[:32], 0

    def mix_key_and_hash(self, ikm):
        self.ck, th, tk = self._hkdf(ikm, 3)
        self.mix_hash(th)
        self.k, self.n = tk[:32], 0

    def _nonce(self):
        return bytes(4) + struct.pack("<Q", self.n)

    def encrypt_and_hash(self, pt):
        ct = aead_seal(self.k, self._nonce(), self.h, pt)
        self.n += 1
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct):
        pt = aead_open(self.k, self._nonce(), self.h, ct)
        if pt is None:
            raise AegisError("AEG-LIVE-01", "handshake authentication")
        self.n += 1
        self.mix_hash(ct)
        return pt

    def split(self):
        t1, t2 = self._hkdf(b"", 2)
        return t1[:32], t2[:32]


def live_handshake(live_id, psk_initiator, psk_responder, e_i, e_r):
    """Recipient is the initiator, sender the responder. Ephemerals injected."""
    prologue = ctx("live") + live_id
    I, R = _Sym(prologue), _Sym(prologue)
    # -> psk, e
    I.mix_key_and_hash(psk_initiator)
    ei_pub = x25519(e_i, _X_BASE)
    I.mix_hash(ei_pub)
    I.mix_key(ei_pub)
    m1 = ei_pub + I.encrypt_and_hash(b"")
    R.mix_key_and_hash(psk_responder)
    R.mix_hash(m1[:32])
    R.mix_key(m1[:32])
    R.decrypt_and_hash(m1[32:])
    # <- e, ee
    er_pub = x25519(e_r, _X_BASE)
    R.mix_hash(er_pub)
    R.mix_key(er_pub)
    R.mix_key(x25519(e_r, m1[:32]))
    m2 = er_pub + R.encrypt_and_hash(b"")
    I.mix_hash(m2[:32])
    I.mix_key(m2[:32])
    I.mix_key(x25519(e_i, m2[:32]))
    I.decrypt_and_hash(m2[32:])
    assert I.h == R.h and I.split() == R.split()
    c_i2r, c_r2i = I.split()
    return {"m1": m1, "m2": m2, "h": I.h, "c_i2r": c_i2r, "c_r2i": c_r2i}


def live_frame(key, n, frame):
    return aead_seal(key, bytes(4) + struct.pack("<Q", n), b"", frame)


def direct_psk(h, live_psk):
    return lexpand(lextract(b"", "direct", h + live_psk), "direct psk", b"", 32)


# --------------------------------------------------------------------------
# Self-tests against published vectors
# --------------------------------------------------------------------------

def selftest():
    H = bytes.fromhex
    r = {}

    # RFC 5869 A.1 (SHA-256) exercises the HKDF code path.
    prk = hkdf_extract(H("000102030405060708090a0b0c"), H("0b" * 22), "sha256")
    okm = hkdf_expand(prk, H("f0f1f2f3f4f5f6f7f8f9"), 42, "sha256")
    r["hkdf_rfc5869_a1"] = (
        prk == H("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        and okm == H("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    )

    # RFC 8439 2.3.2: ChaCha20 block function.
    blk = chacha20_block(bytes(range(32)), 1, H("000000090000004a00000000"))
    r["chacha20_block_rfc8439_2_3_2"] = blk[:16] == H("10f1e7e4d13b5915500fdd1fa32071c4")

    # RFC 8439 2.5.2: Poly1305.
    tag = poly1305(
        H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
        b"Cryptographic Forum Research Group",
    )
    r["poly1305_rfc8439_2_5_2"] = tag == H("a8061dc1305136c6c22b8baf0c0127a9")

    # RFC 8439 2.8.2: AEAD.
    key = bytes(range(0x80, 0xA0))
    nonce = H("070000004041424344454647")
    aad = H("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    boxed = aead_seal(key, nonce, aad, pt)
    r["aead_rfc8439_2_8_2"] = (
        boxed[:16] == H("d31a8d34648e60db7b86afbc53ef7ec2")
        and boxed[-16:] == H("1ae10b594f09e26a7e902ecbd0600691")
        and aead_open(key, nonce, aad, boxed) == pt
        and aead_open(key, nonce, aad, boxed[:-1] + bytes([boxed[-1] ^ 1])) is None
    )

    # RFC 8032 7.1 test 1.
    seed = H("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = H("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = H("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    r["ed25519_rfc8032_test1"] = (
        ed_public(seed) == pub and ed_sign(seed, b"") == sig and ed_verify_strict(pub, b"", sig)
    )

    # Strict verification: S + L, small-order key, small-order R must all be rejected.
    s_plus_l = sig[:32] + (int.from_bytes(sig[32:], "little") + _L).to_bytes(32, "little")
    ident = (1).to_bytes(32, "little")
    r["ed25519_strict_rejections"] = (
        not ed_verify_strict(pub, b"", s_plus_l)
        and not ed_verify_strict(ident, b"", sig)
        and not ed_verify_strict(pub, b"", ident + sig[32:])
        and not ed_verify_strict(pub, b"x", sig)
    )

    # RFC 7748 6.1.
    a = H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bpriv = H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    r["x25519_rfc7748_6_1"] = (
        x25519(a, _X_BASE) == H("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        and x25519(a, x25519(bpriv, _X_BASE))
        == H("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    )

    r["padme_examples"] = (
        padme(65536) == 65536 and padme(65537) == 67584
        and padme(1000000) == 1015808 and padme(1073741825) == 1107296256
    )
    r["base32_roundtrip"] = all(b32dec(b32enc(bytes(range(n)))) == bytes(range(n)) for n in range(1, 70))
    return r


# --------------------------------------------------------------------------
# Vector generation
# --------------------------------------------------------------------------

def tv(name, n):
    """Deterministic test bytes: SHA-512("AEGIS test " || name || u32(i)) in counter mode."""
    out, i = b"", 0
    while len(out) < n:
        out += sha512(b"AEGIS test " + name.encode() + u32(i))
        i += 1
    return out[:n]


def expect(code, fn):
    try:
        fn()
    except AegisError as e:
        return e.code == code, e.code
    return False, "accepted"


def flip(data, offset, bit=0):
    b = bytearray(data)
    b[offset] ^= 1 << bit
    return bytes(b)


def main():
    write = "--check" not in sys.argv
    hx = lambda b: b.hex()
    out = {
        "status": "PROVISIONAL - not yet reproduced by an independent implementation",
        "specification": "Aegis Protocol Specification v3.0 (draft)",
        "generator": "model/aegis_v3_model.py",
        "note": ("Values marked injected stand in for X-Wing or Argon2id outputs, which this model "
                 "does not implement. tv(name, n) is SHA-512('AEGIS test ' || name || u32(i)) in "
                 "counter mode, truncated to n bytes."),
    }

    st = selftest()
    out["selftest"] = st
    failures = [k for k, v in st.items() if not v]
    for k, v in st.items():
        print(f"  selftest  {'ok  ' if v else 'FAIL'}  {k}")
    if failures:
        print("SELF-TEST FAILED:", failures)
        return 1

    out["padme"] = [[n, padme(n)] for n in (2, 3, 65536, 65537, 66000, 100000, 200090, 1000000,
                                             5000000, 1073741824, 1073741825)]
    out["labelled_derivation"] = {
        "ctx('blob id')": hx(ctx("blob id")),
        "LExtract('', 'artifact', 00*33)": hx(lextract(b"", "artifact", bytes(33))),
        "LExpand(00*64, 'blob id', '', 32)": hx(lexpand(bytes(64), "blob id", b"", 32)),
        "LExpand(00*64, 'chain', '', 64)": hx(lexpand(bytes(64), "chain", b"", 64)),
        "LHash('transcript', '')": hx(lhash("transcript", b"")),
    }

    LS, KS = bytes(range(0x00, 0x20)), bytes(range(0x20, 0x40))
    origin = "https://drop.example.org"
    signer_seed = tv("signer seed", 32)
    rcpt_ik_seed, rcpt_ik_pub = identity_from_seed(tv("recipient seed", 32))
    addressed = {"ik_pub": rcpt_ik_pub, "kem_pub": tv("kem_pub", KEM_PK_LEN),
                 "kem_ct": tv("kem_ct", KEM_CT_LEN), "ss_kem": tv("ss_kem", 32)}
    passphrase = {"pw_profile": 0x01, "pw_salt": tv("pw_salt", 16), "pw_key": tv("pw_key", 32)}
    big = bytes((i * 7 + 3) % 251 for i in range(200000))

    cases = [
        ("sealed-split", dict(content=b"Hello, Aegis.", name="hello.txt", media_type="text/plain",
                              LS=LS, KS=KS, origin=origin)),
        ("sealed", dict(content=b"Hello, Aegis.", name="hello.txt", media_type="text/plain",
                        LS=LS, origin=origin)),
        ("sealed-split-signed", dict(content=b"Signed content.", name="signed.txt",
                                     media_type="text/plain", LS=tv("LS signed", 32),
                                     KS=tv("KS signed", 32), origin=origin, signer_seed=signer_seed,
                                     note="For your eyes only.", burn=True)),
        ("addressed-split", dict(content=b"Addressed content.", name="addr.bin",
                                 media_type="application/octet-stream", LS=tv("LS addr", 32),
                                 KS=tv("KS addr", 32), origin=origin, addressed=addressed)),
        ("addressed-passphrase-signed", dict(content=b"All factors.", name="all.txt",
                                             media_type="text/plain", LS=tv("LS all", 32),
                                             KS=tv("KS all", 32), origin="http://aegisexampleonion.onion",
                                             addressed=addressed, passphrase=passphrase,
                                             signer_seed=signer_seed, live=True)),
        ("multi-chunk", dict(content=big, name="pattern.bin", media_type="application/octet-stream",
                             LS=tv("LS big", 32), KS=tv("KS big", 32), origin=origin)),
    ]

    sealed, vectors, ok = {}, [], True
    for name, kw in cases:
        s = seal(**kw)
        sealed[name] = (s, kw)
        cands = [(addressed["ik_pub"], addressed["kem_pub"], addressed["ss_kem"])] if kw.get("addressed") else []
        o = open_blob(s["link"], s["key"], s["blob"], kem_candidates=cands,
                      pw_key=kw["passphrase"]["pw_key"] if kw.get("passphrase") else None)
        good = (o["content"] == kw["content"] and o["name"] == kw["name"]
                and o["blob_id"] == s["a"]["blob_id"]
                and (o["signer"] == ed_public(kw["signer_seed"]) if kw.get("signer_seed") else o["signer"] is None)
                and len(s["blob"]) == HDR_LEN + len(s["P"]) + TAG * (-(-len(s["P"]) // CHUNK)))
        ok &= good
        print(f"  roundtrip {'ok  ' if good else 'FAIL'}  {name}  blob={len(s['blob'])} bytes")
        content = kw["content"]
        inp = {
            "LS": hx(kw["LS"]), "KS": hx(kw["KS"]) if kw.get("KS") else None, "origin": kw["origin"],
            "live": kw.get("live", False), "name": kw["name"], "media_type": kw["media_type"],
            "content": hx(content) if len(content) <= 64 else None,
            "content_rule": None if len(content) <= 64 else "byte i = (i*7 + 3) mod 251",
            "content_len": len(content), "content_sha512": hx(sha512(content)),
            "note": kw.get("note"), "burn": kw.get("burn", False),
            "signer_seed": hx(kw["signer_seed"]) if kw.get("signer_seed") else None,
        }
        if kw.get("addressed"):
            inp["addressed_injected"] = {k: (hx(v) if len(v) <= 64 else "tv('%s', %d)" % (
                {"kem_pub": "kem_pub", "kem_ct": "kem_ct"}[k], len(v))) for k, v in addressed.items()}
        if kw.get("passphrase"):
            inp["passphrase_injected"] = {"pw_profile": 1, "pw_salt": hx(passphrase["pw_salt"]),
                                          "pw_key": hx(passphrase["pw_key"])}
        a, b = s["a"], s["b"]
        vectors.append({
            "name": name, "inputs": inp,
            "artifacts": {"link": s["link"], "key": s["key"]},
            "stage_a": {k: hx(a[k]) for k in ("PRK_A", "blob_id", "K_hdr", "T_burn", "live_id", "live_psk", "chain")},
            "mode": a["mode"],
            "header": {"hp_first_32": hx(s["hp"][:32]), "hp_sha512": hx(sha512(s["hp"])),
                       "oh_sha512": hx(sha512(s["oh"])), "oh_tag": hx(s["oh"][-16:])},
            "rcpt": hx(s["rcpt"]), "transcript": hx(s["th"]),
            "stage_b": {k: hx(b[k]) for k in ("PRK_B", "commit", "K_payload")},
            "stream": {"manifest": hx(s["manifest"]), "n": s["n"], "P_len": len(s["P"]),
                       "chunks": -(-len(s["P"]) // CHUNK),
                       "signature": hx(s["P"][-64:]) if kw.get("signer_seed") else None},
            "blob": {"length": len(s["blob"]), "sha512": hx(sha512(s["blob"])),
                     "first_chunk_tag": hx(split_chunks(s["blob"])[0][-TAG:])},
            "delete_verifier_of_T_burn": hx(verifier(a["T_burn"])),
        })
    out["vectors"] = vectors

    # ---- Negative vectors ---------------------------------------------------
    neg = []

    def record(name, base, mutation, code, fn):
        nonlocal ok
        good, got = expect(code, fn)
        ok &= good
        neg.append({"name": name, "base": base, "mutation": mutation, "expect": code})
        print(f"  negative  {'ok  ' if good else 'FAIL'}  {name}  -> {got}")

    s, kw = sealed["sealed-split-signed"]
    L, K, B = s["link"], s["key"], s["blob"]
    base = "sealed-split-signed"
    op = lambda blob, link=L, key=K: (lambda: open_blob(link, key, blob))

    for off, what, code in [(0, "sealed header, first byte", "AEG-CRYPTO-01"),
                            (1167, "sealed header, last tag byte", "AEG-CRYPTO-01"),
                            (1168, "commitment, first byte", "AEG-CRYPTO-02"),
                            (1199, "commitment, last byte", "AEG-CRYPTO-02"),
                            (1200, "chunk 0, first byte", "AEG-CRYPTO-03"),
                            (len(B) - 1, "chunk 0, last tag byte", "AEG-CRYPTO-03")]:
        record(f"bit flip: {what}", base, {"op": "flip", "offset": off, "bit": 0}, code, op(flip(B, off)))
    record("truncate by 1 byte", base, {"op": "truncate", "bytes": 1}, "AEG-CRYPTO-03", op(B[:-1]))
    record("append 1 byte", base, {"op": "append", "hex": "00"}, "AEG-FMT-03", op(B + b"\x00"))
    record("blob shorter than header + 17", base, {"op": "keep", "bytes": 1216}, "AEG-FMT-03", op(B[:1216]))
    record("wrong ShareKey", base, {"op": "key", "KS": hx(KS)}, "AEG-CRYPTO-01", op(B, L, encode_key(KS)))
    record("ShareKey missing for SPLIT link", base, {"op": "key", "KS": None}, "AEG-FMT-01", op(B, L, None))

    raw = b32dec(L[11:])
    record("link: checksum bit flipped", base, {"op": "artifact", "text": "aegis:link:" + b32enc(flip(raw, len(raw) - 1))},
           "AEG-FMT-01", lambda: decode_link("aegis:link:" + b32enc(flip(raw, len(raw) - 1))))
    record("link: version 0x04", base, {"op": "artifact", "text": "aegis:link:" + b32enc(b"\x04" + raw[1:])},
           "AEG-FMT-02", lambda: decode_link("aegis:link:" + b32enc(b"\x04" + raw[1:])))
    body = raw[:1] + bytes([raw[1] | 0x80]) + raw[2:-4]
    resv = "aegis:link:" + b32enc(body + lhash("link check", body)[:4])
    record("link: reserved lflags bit set, checksum valid", base, {"op": "artifact", "text": resv},
           "AEG-FMT-01", lambda: decode_link(resv))
    kraw = b32dec(K[10:])
    noncanon = K[:-1] + _B32[_B32.index(K[-1]) | 1]
    record("key: non-canonical base32 trailing bits", base, {"op": "artifact", "text": noncanon},
           "AEG-FMT-01", lambda: decode_key(noncanon))
    record("key: padding character", base, {"op": "artifact", "text": K + "="},
           "AEG-FMT-01", lambda: decode_key(K + "="))
    spaced = "aegis:key:" + " ".join(K[10:][i:i + 4] for i in range(0, 60, 4)).upper()
    good = decode_key(spaced) == kraw[1:33]
    ok &= good
    print(f"  positive  {'ok  ' if good else 'FAIL'}  key: upper case with spaces is accepted")
    out["artifact_text_tolerance"] = {"text": spaced, "decodes_to_KS": hx(kraw[1:33])}

    # Crafted by a malicious sender: valid cryptography, invalid structure.
    cLS, cKS = tv("LS craft", 32), tv("KS craft", 32)
    clink, ckey = encode_link(cLS, origin, True), encode_key(cKS)

    def craft(name, code, hp, P_fn, mutation):
        a, oh, th, b = derive(cLS, cKS, hp)
        P = P_fn(th, b)
        blob = assemble(oh, b, P)
        mutation = dict(mutation, LS=hx(cLS), KS=hx(cKS), hp_first_32=hx(hp[:32]),
                        P_len=len(P), P_sha512=hx(sha512(P)), blob_sha512=hx(sha512(blob)))
        record(name, "crafted", mutation, code, lambda: open_blob(clink, ckey, blob))

    def stream(manifest, content=b"", plen=CHUNK, tail=b""):
        return manifest + content + bytes(plen - len(manifest) - len(content) - len(tail)) + tail

    mf = build_manifest(4, "x", "a/b")
    hp0 = build_hp(0)
    craft("non-zero padding byte", "AEG-FMT-04", hp0,
          lambda th, b: flip(stream(mf, b"data"), CHUNK - 1), {"craft": "last pad byte = 0x01"})
    craft("padded length is not a Padme value", "AEG-FMT-04", hp0,
          lambda th, b: stream(mf, b"data", CHUNK + 1), {"craft": "|P| = 65537"})
    craft("padded length below minimum", "AEG-FMT-04", hp0,
          lambda th, b: stream(mf, b"data", 4096), {"craft": "|P| = 4096"})
    craft("content_len exceeds stream", "AEG-FMT-04", hp0,
          lambda th, b: stream(build_manifest(1 << 40, "x", "a/b")), {"craft": "content_len = 2^40"})
    craft("extensions out of order", "AEG-FMT-04", hp0,
          lambda th, b: stream(build_manifest(0, "x", "a/b", exts=[(EXT_BURN, b""), (EXT_NOTE, b"n")])),
          {"craft": "burn before note"})
    craft("extension repeated", "AEG-FMT-04", hp0,
          lambda th, b: stream(build_manifest(0, "x", "a/b", exts=[(EXT_NOTE, b"a"), (EXT_NOTE, b"b")])),
          {"craft": "note twice"})
    craft("unknown critical extension", "AEG-FMT-04", hp0,
          lambda th, b: stream(build_manifest(0, "x", "a/b", exts=[(0x8001, b"")])), {"craft": "type 0x8001"})
    craft("media_type contains a space", "AEG-FMT-04", hp0,
          lambda th, b: stream(build_manifest(0, "x", "a b")), {"craft": "media_type 'a b'"})
    craft("name is not UTF-8", "AEG-FMT-04", hp0,
          lambda th, b: stream(mf.replace(b"\x00\x01x", b"\x00\x01\xff")), {"craft": "name = 0xff"})
    craft("sender_ik set without SIGNED", "AEG-FMT-04", hp0,
          lambda th, b: stream(build_manifest(0, "x", "a/b", sender_ik=ed_public(signer_seed))),
          {"craft": "sender_ik non-zero, hflags = 0"})
    craft("SIGNED with zero sender_ik", "AEG-FMT-04", build_hp(H_SIGNED),
          lambda th, b: stream(build_manifest(0, "x", "a/b")), {"craft": "hflags SIGNED, sender_ik zero"})
    craft("header: reserved byte set", "AEG-FMT-03", flip(hp0, 2),
          lambda th, b: stream(mf, b"data"), {"craft": "hp[2] = 0x01"})
    craft("header: reserved flag bit set", "AEG-FMT-03", build_hp(0x08),
          lambda th, b: stream(mf, b"data"), {"craft": "hflags = 0x08"})
    craft("header: kem_ct non-zero without ADDRESSED", "AEG-FMT-03", flip(hp0, HP_LEN - 1),
          lambda th, b: stream(mf, b"data"), {"craft": "last kem_ct byte = 0x01"})
    craft("header: pw_salt non-zero without PASSPHRASE", "AEG-FMT-03", flip(hp0, 16),
          lambda th, b: stream(mf, b"data"), {"craft": "pw_salt[0] = 0x01"})
    craft("header: undefined pw_profile", "AEG-FMT-03",
          build_hp(H_PASSPHRASE, pw_profile=3, pw_salt=tv("pw_salt", 16)),
          lambda th, b: stream(mf, b"data"), {"craft": "pw_profile = 0x03"})

    smf = build_manifest(4, "x", "a/b", sender_ik=ed_public(signer_seed))
    hps = build_hp(H_SIGNED)

    def signed_stream(th, b, mangle):
        p0 = stream(smf, b"data", CHUNK - 64)
        sig = lsign(signer_seed, "sender signature", sender_sig_message(th, b["commit"], p0))
        return p0 + mangle(sig)

    craft("signature: one bit flipped", "AEG-AUTH-01", hps,
          lambda th, b: signed_stream(th, b, lambda sg: flip(sg, 40)), {"craft": "sig[40] ^= 1"})
    craft("signature: non-canonical S (S + L)", "AEG-AUTH-01", hps,
          lambda th, b: signed_stream(th, b, lambda sg: sg[:32] + (int.from_bytes(sg[32:], "little") + _L).to_bytes(32, "little")),
          {"craft": "S replaced by S + L"})
    craft("signature: small-order R", "AEG-AUTH-01", hps,
          lambda th, b: signed_stream(th, b, lambda sg: (1).to_bytes(32, "little") + sg[32:]),
          {"craft": "R = identity point"})
    ident = (1).to_bytes(32, "little")
    craft("signature: small-order signer key", "AEG-AUTH-01", hps,
          lambda th, b: stream(build_manifest(4, "x", "a/b", sender_ik=ident), b"data", CHUNK - 64) + ident + bytes(32),
          {"craft": "sender_ik = identity point, sig = (identity, 0)"})
    craft("signature made for a different transcript", "AEG-AUTH-01", hps,
          lambda th, b: (lambda p0: p0 + lsign(signer_seed, "sender signature",
                                                 sender_sig_message(bytes(64), b["commit"], p0)))(stream(smf, b"data", CHUNK - 64)),
          {"craft": "signed with TH = 0^64"})

    # Stream structure, on the four-chunk vector.
    s4, _ = sealed["multi-chunk"]
    B4, base4 = s4["blob"], "multi-chunk"
    op4 = lambda blob: (lambda: open_blob(s4["link"], s4["key"], blob))
    c = [B4[HDR_LEN + i * ENC_CHUNK: HDR_LEN + (i + 1) * ENC_CHUNK] for i in range(4)]
    record("chunks 0 and 1 swapped", base4, {"op": "swap_chunks", "i": 0, "j": 1}, "AEG-CRYPTO-03",
           op4(B4[:HDR_LEN] + c[1] + c[0] + c[2] + c[3]))
    record("final chunk removed", base4, {"op": "drop_chunk", "i": 3}, "AEG-CRYPTO-03",
           op4(B4[:HDR_LEN] + c[0] + c[1] + c[2]))
    record("chunk 1 duplicated", base4, {"op": "dup_chunk", "i": 1}, "AEG-CRYPTO-03",
           op4(B4[:HDR_LEN] + c[0] + c[1] + c[1] + c[2] + c[3]))
    record("bit flip in chunk 2", base4, {"op": "flip", "offset": HDR_LEN + 2 * ENC_CHUNK + 5, "bit": 0},
           "AEG-CRYPTO-03", op4(flip(B4, HDR_LEN + 2 * ENC_CHUNK + 5)))

    # Addressed and passphrase factors.
    sa, _ = sealed["addressed-split"]
    cand = (addressed["ik_pub"], addressed["kem_pub"], addressed["ss_kem"])
    record("addressed: wrong KEM shared secret", "addressed-split", {"op": "factor", "ss_kem": "tv('other', 32)"},
           "AEG-CRYPTO-02", lambda: open_blob(sa["link"], sa["key"], sa["blob"],
                                              kem_candidates=[(cand[0], cand[1], tv("other", 32))]))
    record("addressed: right secret, different recipient identity key", "addressed-split",
           {"op": "factor", "ik_pub": "ed_public(tv('other', 32))"}, "AEG-CRYPTO-02",
           lambda: open_blob(sa["link"], sa["key"], sa["blob"],
                             kem_candidates=[(ed_public(tv("other", 32)), cand[1], cand[2])]))
    record("addressed: no local key", "addressed-split", {"op": "factor", "kem_candidates": []},
           "AEG-CRYPTO-02", lambda: open_blob(sa["link"], sa["key"], sa["blob"]))
    sp, _ = sealed["addressed-passphrase-signed"]
    record("passphrase: wrong pw_key", "addressed-passphrase-signed", {"op": "factor", "pw_key": "tv('other', 32)"},
           "AEG-CRYPTO-02", lambda: open_blob(sp["link"], sp["key"], sp["blob"], kem_candidates=[cand],
                                              pw_key=tv("other", 32)))
    good = open_blob(sa["link"], sa["key"], sa["blob"],
                     kem_candidates=[(cand[0], cand[1], tv("old key", 32)), cand])["content"] == b"Addressed content."
    ok &= good
    print(f"  positive  {'ok  ' if good else 'FAIL'}  addressed: second candidate key selected by commitment")
    out["negative"] = neg

    # ---- Identity -----------------------------------------------------------
    seed = tv("recovery seed", 32)
    ik_seed, ik_pub = identity_from_seed(seed)
    kem_pub = tv("kem_pub", KEM_PK_LEN)
    card = make_card(ik_seed, kem_pub, 1_800_000_000, 1_800_000_000 + MAX_CARD_WINDOW)
    v = validate_card(card, 1_800_000_001)
    checks = [
        ("card validates", v["ik_pub"] == ik_pub and v["kem_pub"] == kem_pub),
        ("card: expired", expect("AEG-AUTH-02", lambda: validate_card(card, 1_800_000_000 + MAX_CARD_WINDOW))[0]),
        ("card: signature bit flipped", expect("AEG-AUTH-02", lambda: validate_card(
            (lambda c: c[:-4] + lhash("card check", c[:-4])[:4])(flip(card, 1300)), 1_800_000_001))[0]),
        ("card: window over 90 days", expect("AEG-AUTH-02", lambda: validate_card(
            make_card(ik_seed, kem_pub, 1_800_000_000, 1_800_000_001 + MAX_CARD_WINDOW), 1_800_000_001))[0]),
        ("card: kem_pub substituted", expect("AEG-AUTH-02", lambda: validate_card(
            (lambda c: c[:-4] + lhash("card check", c[:-4])[:4])(flip(card, 100)), 1_800_000_001))[0]),
    ]
    for nme, g in checks:
        ok &= g
        print(f"  identity  {'ok  ' if g else 'FAIL'}  {nme}")
    out["identity"] = {
        "seed": hx(seed), "ik_seed": hx(ik_seed), "ik_pub": hx(ik_pub), "fingerprint": fingerprint(ik_pub),
        "card": {"kem_pub": "tv('kem_pub', 1216) (injected)", "not_before": 1_800_000_000,
                 "not_after": 1_800_000_000 + MAX_CARD_WINDOW, "length": len(card),
                 "signature": hx(card[1265:1329]), "check": hx(card[-4:]), "sha512": hx(sha512(card)),
                 "text_prefix": ("aegis:card:" + b32enc(card))[:48] + "..."},
    }

    # ---- Storage service helpers -------------------------------------------
    a0 = sealed["sealed-split"][0]["a"]
    chal = tv("pow challenge", 32)
    ctr = pow_solve(chal, a0["blob_id"], 12)
    good = pow_valid(chal, a0["blob_id"], ctr, 12) and not pow_valid(chal, a0["live_id"], ctr, 12)
    ok &= good
    print(f"  service   {'ok  ' if good else 'FAIL'}  proof-of-work stamp is bound to the blob address")
    t_owner = tv("T_owner", 32)
    out["service"] = {
        "delete_verifier": {"T_owner": hx(t_owner), "verifier": hx(verifier(t_owner))},
        "pow": {"challenge": hx(chal), "id": hx(a0["blob_id"]), "bits": 12, "counter": ctr,
                "stamp": "pow-sha512." + hx(chal) + "." + hx(u64(ctr)),
                "digest": hx(lhash("pow", chal + a0["blob_id"] + u64(ctr)))},
    }

    # ---- Live handshake ----------------------------------------------------
    e_i, e_r = tv("live e initiator", 32), tv("live e responder", 32)
    hs = live_handshake(a0["live_id"], a0["live_psk"], a0["live_psk"], e_i, e_r)
    good = len(hs["m1"]) == 48 and len(hs["m2"]) == 48
    bad_psk, _ = expect("AEG-LIVE-01", lambda: live_handshake(a0["live_id"], tv("wrong psk", 32), a0["live_psk"], e_i, e_r))
    # A peer using a different live_id has a different prologue, hence a different
    # handshake state from the first byte; its first message cannot authenticate.
    bad_id = _Sym(ctx("live") + a0["live_id"]).h != _Sym(ctx("live") + a0["blob_id"]).h
    ok &= good and bad_psk and bad_id
    print(f"  live      {'ok  ' if good else 'FAIL'}  handshake completes; both messages are 48 bytes")
    print(f"  live      {'ok  ' if bad_psk else 'FAIL'}  wrong PSK is rejected on the first message")
    print(f"  live      {'ok  ' if bad_id else 'FAIL'}  different prologue gives a different handshake state")
    blob_len = len(sealed["sealed-split"][0]["blob"])
    out["live"] = {
        "status": "PROVISIONAL - to be confirmed against an independent Noise implementation (plan M7)",
        "protocol": NOISE_NAME.decode(), "prologue": hx(ctx("live") + a0["live_id"]),
        "psk": hx(a0["live_psk"]), "e_initiator": hx(e_i), "e_responder": hx(e_r),
        "message_1": hx(hs["m1"]), "message_2": hx(hs["m2"]), "handshake_hash": hx(hs["h"]),
        "key_initiator_to_responder": hx(hs["c_i2r"]), "key_responder_to_initiator": hx(hs["c_r2i"]),
        "frames": {
            "HELLO (sender, n=0)": hx(live_frame(hs["c_r2i"], 0, b"\x01" + u64(blob_len))),
            "READY (recipient, n=0)": hx(live_frame(hs["c_i2r"], 0, b"\x02" + u64(0))),
        },
        "direct_psk": hx(direct_psk(hs["h"], a0["live_psk"])),
    }

    print()
    if not ok:
        print("MODEL CHECKS FAILED")
        return 1
    print(f"All checks passed: {len(st)} self-tests, {len(vectors)} round-trips, {len(neg)} negative vectors.")
    if write:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors_v3_provisional.json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(out, f, indent=1)
            f.write("\n")
        print("Wrote", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
