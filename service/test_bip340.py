"""BIP-340 against the official vectors, and bech32 round trips."""
import csv
import os

import bip340

VECTORS = os.path.join(os.path.dirname(__file__), "..", "test", "fixtures", "bip340-vectors.csv")


def test_official_vectors():
    with open(VECTORS) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) >= 15
    for row in rows:
        msg = bytes.fromhex(row["message"])
        pub = bytes.fromhex(row["public key"])
        sig = bytes.fromhex(row["signature"])
        expected = row["verification result"].strip().upper() == "TRUE"
        if row["secret key"]:
            sec = bytes.fromhex(row["secret key"])
            aux = bytes.fromhex(row["aux_rand"])
            assert bip340.pubkey_of(sec) == pub, row["index"]
            assert bip340.sign(msg, sec, aux) == sig, row["index"]
        assert bip340.verify(msg, pub, sig) is expected, row["index"]


def test_sign_verify_random_key():
    sec = os.urandom(32)
    pub = bip340.pubkey_of(sec)
    msg = os.urandom(32)
    sig = bip340.sign(msg, sec)
    assert bip340.verify(msg, pub, sig)
    assert not bip340.verify(bytes(32), pub, sig)
    assert not bip340.verify(msg, pub, sig[:-1] + bytes([sig[-1] ^ 1]))


def test_npub_round_trip():
    pub = bytes.fromhex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
    text = bip340.npub(pub)
    assert text.startswith("npub1")
    assert bip340.pubkey_from(text) == pub
    assert bip340.pubkey_from(pub.hex()) == pub
    assert bip340.pubkey_from("npub1garbage") is None
    assert bip340.pubkey_from("zz") is None
    # a known pair from the nostr ecosystem (fiatjaf)
    assert bip340.npub(pub) == "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
