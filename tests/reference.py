"""Differential tests: compare apis/xEncrypt.lua with independent Python implementations.

SHA-256, HMAC and PBKDF2 come from hashlib/hmac, ChaCha20 from the `cryptography`
package (OpenSSL), and the token format and password hash format are rebuilt
here from their documentation, in both directions. Used by run_tests.py.
"""
import codecs
import hashlib
import hmac
import random

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:  # pragma: no cover - optional dependency
    Cipher = None

BOOT = r"""
local root = ...
local cc = dofile(root .. "/tests/cc_env.lua")
cc.root = root
local computer = cc.newComputer(1)
return computer:loadAPI("apis/xEncrypt.lua"), computer:loadAPI("apis/Unicode.lua")
"""

# Invalid UTF-8 bytes stand for themselves (as in the CC charset).
codecs.register_error("xencrypt-bytes", lambda e: ("".join(chr(b) for b in e.object[e.start:e.end]), e.end))


def chacha20_ref(key, nonce, counter, data):
    cipher = Cipher(algorithms.ChaCha20(key, counter.to_bytes(4, "little") + nonce), mode=None)
    return cipher.encryptor().update(data)


def hkdf_ref(ikm, salt, info, length):
    prk = hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()
    okm, block, i = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def token_ref(key_hex, plaintext, aad, nonce):
    key = bytes.fromhex(key_hex)
    enc_key = hmac.new(key, b"xEncrypt v1 encryption", hashlib.sha256).digest()
    mac_key = hmac.new(key, b"xEncrypt v1 authentication", hashlib.sha256).digest()
    header = b"\x01" + nonce
    ciphertext = chacha20_ref(enc_key, nonce, 1, plaintext)
    tag = hmac.new(mac_key, header + len(aad).to_bytes(8, "big") + aad + ciphertext, hashlib.sha256).digest()
    return (header + ciphertext + tag).hex()


def open_token_ref(key_hex, token, aad):
    key, data = bytes.fromhex(key_hex), bytes.fromhex(token)
    enc_key = hmac.new(key, b"xEncrypt v1 encryption", hashlib.sha256).digest()
    mac_key = hmac.new(key, b"xEncrypt v1 authentication", hashlib.sha256).digest()
    header, ciphertext, tag = data[:13], data[13:-32], data[-32:]
    expected = hmac.new(mac_key, header + len(aad).to_bytes(8, "big") + aad + ciphertext, hashlib.sha256).digest()
    assert data[0] == 1 and hmac.compare_digest(tag, expected), "tag mismatch"
    return chacha20_ref(enc_key, header[1:], 1, ciphertext)


def run(module, root):
    """Returns (passed, failed, skipped, failure text) for one lupa runtime module."""
    lua = module.LuaRuntime(unpack_returned_tuples=True, encoding=None)
    X, U = lua.execute(BOOT, root.encode())
    rng = random.Random(1234)
    results = {"passed": 0, "failed": 0, "skipped": 0, "failures": []}

    def check(name, fn):
        try:
            fn()
            results["passed"] += 1
        except Exception as exc:  # report and keep going
            results["failed"] += 1
            results["failures"].append(f"{name}: {type(exc).__name__}: {exc}")

    def rbytes(n):
        return bytes(rng.getrandbits(8) for _ in range(n))

    def sha():
        for n in list(range(0, 130)) + [183, 191, 192, 200, 255, 256, 1000, 4099]:
            data = rbytes(n)
            assert X.sha256(data) == hashlib.sha256(data).digest(), f"length {n}"

    def mac():
        for klen in (0, 1, 31, 32, 63, 64, 65, 100, 200):
            for dlen in (0, 1, 55, 56, 64, 119, 120, 300):
                key, data = rbytes(klen), rbytes(dlen)
                assert X.hmac(key, data) == hmac.new(key, data, hashlib.sha256).digest(), f"key {klen} data {dlen}"

    def pbkdf():
        for iterations, length in ((1, 1), (2, 31), (3, 32), (5, 33), (10, 64), (7, 100)):
            pw, salt = rbytes(rng.randint(0, 80)), rbytes(rng.randint(0, 40))
            want = hashlib.pbkdf2_hmac("sha256", pw, salt, iterations, length)
            assert X.pbkdf2(pw, salt, iterations, length) == want, f"{iterations} iterations, {length} bytes"

    def hk():
        for length in (0, 1, 32, 33, 64, 100, 255):
            ikm, salt, info = rbytes(rng.randint(0, 80)), rbytes(rng.choice((0, 13, 32, 80))), rbytes(rng.randint(0, 40))
            assert X.hkdf(ikm, salt, info, length) == hkdf_ref(ikm, salt, info, length), f"length {length}"

    def chacha():
        for n in list(range(0, 70)) + [127, 128, 129, 200, 1000]:
            key, nonce, counter, data = rbytes(32), rbytes(12), rng.choice((0, 1, 7, 2**31, 2**32 - 20)), rbytes(n)
            assert X.chacha20(key, nonce, counter, data) == chacha20_ref(key, nonce, counter, data), f"length {n}"

    def tokens_lua_to_python():
        for n in (0, 1, 63, 64, 65, 500):
            key = X.generateKey().decode()
            aad, plaintext = rbytes(rng.randint(0, 20)), rbytes(n)
            token = X.encrypt(key.encode(), plaintext, aad).decode()
            assert open_token_ref(key, token, aad) == plaintext, f"length {n}"

    def tokens_python_to_lua():
        for n in (0, 1, 64, 300):
            key = rbytes(32).hex()
            aad, plaintext = rbytes(rng.randint(0, 20)), rbytes(n)
            token = token_ref(key, plaintext, aad, rbytes(12))
            assert X.decrypt(key.encode(), token.encode(), aad) == plaintext, f"length {n}"

    def passwords():
        stored = X.hashPassword(b"open sesame", 7).decode()
        _, iterations, salt, digest = stored.split("$")
        assert hashlib.pbkdf2_hmac("sha256", b"open sesame", bytes.fromhex(salt), int(iterations), 32).hex() == digest
        salt = rbytes(16)
        made = "pbkdf2-sha256$9$%s$%s" % (salt.hex(), hashlib.pbkdf2_hmac("sha256", b"pw", salt, 9, 32).hex())
        assert X.verifyPassword(b"pw", made.encode()) is True
        assert X.verifyPassword(b"pX", made.encode()) is False

    def unicode_decoding():
        # Random bytes biased towards UTF-8 lead and continuation bytes.
        pool = list(range(0x20, 0x7F)) + list(range(0x80, 0xC0)) * 2 + list(range(0xC0, 0x100)) * 2
        for n in range(1, 400):
            data = bytes(rng.choice(pool) for _ in range(rng.randint(1, 12)))
            want = "".join("U+%04X" % ord(ch) for ch in data.decode("utf-8", "xencrypt-bytes"))
            assert U.transcodeUTF8String(data).decode() == want, data.hex()
            text = "".join(chr(rng.choice((rng.randint(0x20, 0x7E), rng.randint(0xA0, 0xFF), rng.randint(0x100, 0xD7FF),
                                          rng.randint(0xE000, 0xFFFD), rng.randint(0x10000, 0x10FFFF))))
                           for _ in range(rng.randint(1, 8)))
            codes = "".join("U+%04X" % ord(ch) for ch in text)
            assert U.transcodeUnicodeString(codes.encode(), True) == text.encode("utf-8"), codes
            assert U.transcodeUTF8String(text.encode("utf-8")).decode() == codes, codes

    check("Unicode vs Python UTF-8 codec", unicode_decoding)
    check("sha256 vs hashlib", sha)
    check("hmac vs hmac module", mac)
    check("pbkdf2 vs hashlib", pbkdf)
    check("hkdf vs reference", hk)
    check("password hash format", passwords)
    if Cipher is None:
        results["skipped"] += 3
    else:
        check("chacha20 vs OpenSSL", chacha)
        check("Lua tokens open in Python", tokens_lua_to_python)
        check("Python tokens open in Lua", tokens_python_to_lua)
    return results["passed"], results["failed"], results["skipped"], "\n\n".join(results["failures"])
