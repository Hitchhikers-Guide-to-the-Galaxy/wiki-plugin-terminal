"""bip340.py — Schnorr signatures over secp256k1 (BIP-340), pure Python.

The reference algorithm, written out so a wiki page's signature can be
checked with nothing installed: no pip, no OpenSSL, no node. Sign and verify
follow BIP-340 to the letter (tagged hashes, x-only keys, even-y nonce and
key), and the official test vectors in test/fixtures/bip340-vectors.csv are
the proof. Keys are shown as npub (BIP-173 bech32, the nostr convention) so
any nostr tool reads them; a signature made here verifies with `nak` and
vice versa.

Slow by design: a verification is a few milliseconds of big-integer
arithmetic, which is nothing beside the page fetch it replaces.
"""
import hashlib
import hmac
import os

# secp256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = tuple[int, int] | None


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _add(P1: Point, P2: Point) -> Point:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] == P2[0] and P1[1] != P2[1]:
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    return (x3, (lam * (P1[0] - x3) - P1[1]) % p)


def _mul(P: Point, k: int) -> Point:
    R = None
    for i in range(256):
        if (k >> i) & 1:
            R = _add(R, P)
        P = _add(P, P)
    return R


def _bytes(x: int) -> bytes:
    return x.to_bytes(32, "big")


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _has_even_y(P: Point) -> bool:
    return P is not None and P[1] % 2 == 0


def lift_x(x: int) -> Point:
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y % 2 == 0 else p - y)


def pubkey_of(seckey: bytes) -> bytes:
    """x-only public key for a 32-byte secret."""
    d0 = _int(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError("secret key out of range")
    P = _mul(G, d0)
    return _bytes(P[0])


def sign(msg: bytes, seckey: bytes, aux_rand: bytes | None = None) -> bytes:
    """BIP-340 allows a message of any length; the wiki always signs a 32-byte
    event id, but the official vectors exercise 0, 17 and 100 bytes too."""
    d0 = _int(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError("secret key out of range")
    aux = aux_rand if aux_rand is not None else os.urandom(32)
    if len(aux) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    P = _mul(G, d0)
    d = d0 if _has_even_y(P) else n - d0
    t = _bytes(d ^ _int(tagged_hash("BIP0340/aux", aux)))
    k0 = _int(tagged_hash("BIP0340/nonce", t + _bytes(P[0]) + msg)) % n
    if k0 == 0:
        raise RuntimeError("nonce is zero")
    R = _mul(G, k0)
    k = n - k0 if not _has_even_y(R) else k0
    e = _int(tagged_hash("BIP0340/challenge", _bytes(R[0]) + _bytes(P[0]) + msg)) % n
    sig = _bytes(R[0]) + _bytes((k + e * d) % n)
    if not verify(msg, _bytes(P[0]), sig):
        raise RuntimeError("the signature failed its own verification")
    return sig


def verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    P = lift_x(_int(pubkey))
    r = _int(sig[0:32])
    s = _int(sig[32:64])
    if P is None or r >= p or s >= n:
        return False
    e = _int(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = _add(_mul(G, s), _mul(P, n - e))
    if R is None or not _has_even_y(R) or R[0] != r:
        return False
    return True


# ── bech32 (BIP-173) for npub / nsec display ──────────────────────────────────
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        return None
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    values = _convertbits(data, 8, 5)
    combined = values + [0] * 6
    mod = _polymod(_hrp_expand(hrp) + combined) ^ 1
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in values + checksum)


def bech32_decode(text: str) -> tuple[str, bytes] | None:
    text = text.lower()
    if "1" not in text:
        return None
    pos = text.rfind("1")
    hrp, data = text[:pos], text[pos + 1:]
    if any(c not in _CHARSET for c in data) or len(data) < 6:
        return None
    values = [_CHARSET.index(c) for c in data]
    if _polymod(_hrp_expand(hrp) + values) != 1:
        return None
    out = _convertbits(values[:-6], 5, 8, False)
    if out is None:
        return None
    return hrp, bytes(out)


def npub(pubkey: bytes) -> str:
    return bech32_encode("npub", pubkey)


def pubkey_from(text: str) -> bytes | None:
    """Accept an npub or 64 hex characters; None for anything else."""
    text = (text or "").strip()
    if text.lower().startswith("npub1"):
        d = bech32_decode(text)
        return d[1] if d and d[0] == "npub" and len(d[1]) == 32 else None
    try:
        b = bytes.fromhex(text)
    except ValueError:
        return None
    return b if len(b) == 32 else None
