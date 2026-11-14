#!/usr/bin/env python3
"""Independent cipher vectors for the HTTP and Stream integration tests."""

import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def encrypt(name, key, iv, data, aad=b"", padded=True):
    mode = name.rsplit("-", 1)[1]
    if mode == "gcm":
        return AESGCM(key).encrypt(iv, data, aad)
    if mode == "poly1305":
        return ChaCha20Poly1305(key).encrypt(iv, data, aad)

    mode_type = {
        "cbc": modes.CBC,
        "ctr": modes.CTR,
        "cfb": modes.CFB,
        "ofb": modes.OFB,
        "ecb": modes.ECB,
    }[mode]
    mode_value = mode_type(iv) if iv else mode_type()
    if padded and mode in ("cbc", "ecb"):
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
    ctx = Cipher(algorithms.AES(key), mode_value).encryptor()
    return ctx.update(data) + ctx.finalize()


def main(root):
    declarations, cases, automatic = [], [], []

    def value(name, raw):
        if raw:
            declarations.append(f"var ${name} hex_decode {raw.hex()};")
        else:
            declarations.append(f'var ${name} set "";')
        return "$" + name

    def add(name, expression, expected):
        index = len(cases)
        declarations.extend([
            f"var $crypto_result_{index} {expression};",
            f"var $crypto_hex_{index} hex_encode $crypto_result_{index};",
        ])
        cases.append({
            "name": name,
            "expected": expected.hex(),
            "variable": f"$crypto_hex_{index}",
        })

    message = b"payload\x00with binary\xff and padding"
    aad = b"tenant\x00one"
    names = [
        f"aes-{bits}-{mode}"
        for bits in (128, 192, 256)
        for mode in ("gcm", "cbc", "ctr", "cfb", "ofb", "ecb")
    ] + ["chacha20-poly1305"]

    for index, name in enumerate(names):
        mode = name.rsplit("-", 1)[1]
        auth = mode in ("gcm", "poly1305")
        operation = "chacha20" if mode == "poly1305" else "aes"
        key_len = 32 if mode == "poly1305" else int(name.split("-")[1]) // 8
        key = bytes(range(key_len))
        iv = bytes(range(12 if auth else 0 if mode == "ecb" else 16))
        k = value(f"crypto_key_{index}", key)
        n = value(f"crypto_iv_{index}", iv)
        m = value(f"crypto_message_{index}", message)
        a = value(f"crypto_aad_{index}", aad)
        encrypted = encrypt(name, key, iv, message, aad)
        raw = value(f"crypto_cipher_{index}", encrypted)
        packed = value(f"crypto_packed_{index}", iv + encrypted)
        iv_option = f" iv={n}" if iv else ""
        aad_option = f" aad={a}" if auth else ""
        cipher_option = f"cipher={name}" if operation == "aes" else ""
        options = cipher_option + aad_option
        raw_options = f"{options}{iv_option} format=raw"

        add(name + " raw encrypt", f"{operation}_encrypt {m} {k} {raw_options}", encrypted)
        add(name + " raw decrypt", f"{operation}_decrypt {raw} {k} {raw_options}", message)
        add(name + " packed encrypt",
            f"{operation}_encrypt {m} {k} {options}{iv_option}", iv + encrypted)
        add(name + " packed decrypt", f"{operation}_decrypt {packed} {k} {options}", message)

        if operation == "aes":
            selector = value(f"crypto_selector_{index}", name.encode())
            dynamic = f"cipher={selector}{aad_option}{iv_option} format=raw"
            add(name + " dynamic cipher encrypt",
                f"aes_encrypt {m} {k} {dynamic}", encrypted)
            add(name + " dynamic cipher decrypt",
                f"aes_decrypt {raw} {k} {dynamic}", message)

        if mode == "gcm":
            default = f"{aad_option}{iv_option} format=raw"
            add(name + " default cipher encrypt",
                f"aes_encrypt {m} {k} {default}", encrypted)
            add(name + " default cipher decrypt",
                f"aes_decrypt {raw} {k} {default}", message)

        if auth:
            altered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
            bad = value(f"crypto_bad_{index}", altered)
            add(name + " bad authentication tag",
                f"{operation}_decrypt {bad} {k} {raw_options}", b"")
            add(name + " wrong AAD",
                f"{operation}_decrypt {raw} {k} {cipher_option}{iv_option} aad=wrong format=raw",
                b"")
            wrong_key = value(f"crypto_wrong_key_{index}", bytes(key_len))
            add(name + " wrong key",
                f"{operation}_decrypt {raw} {wrong_key} {raw_options}", b"")
            short = value(f"crypto_short_{index}", bytes(15))
            add(name + " truncated tag", f"{operation}_decrypt {short} {k} {raw_options}", b"")
            empty = value(f"crypto_empty_ct_{index}",
                          encrypt(name, key, iv, b"", aad))
            add(name + " empty plaintext",
                f"{operation}_decrypt {empty} {k} {raw_options}", b"")

        if mode in ("cbc", "ecb"):
            plain = bytes(range(32))
            exact = encrypt(name, key, iv, plain, padded=False)
            src = value(f"crypto_unpadded_{index}", plain)
            ct = value(f"crypto_unpadded_ct_{index}", exact)
            unpadded = f"{cipher_option}{iv_option} padding=none format=raw"
            add(name + " no padding encrypt", f"{operation}_encrypt {src} {k} {unpadded}", exact)
            add(name + " no padding decrypt", f"{operation}_decrypt {ct} {k} {unpadded}", plain)
            add(name + " incomplete block encrypt",
                f"{operation}_encrypt short {k} {unpadded}", b"")
            short = value(f"crypto_bad_block_{index}", bytes(15))
            add(name + " incomplete block decrypt",
                f"{operation}_decrypt {short} {k} {unpadded}", b"")

        if index in (0, 1, 5, 18):
            for length in (0, 15, 16, 17, 257):
                plain = bytes(i % 256 for i in range(length))
                ciphertext = encrypt(name, key, iv, plain, aad)
                src = value(f"crypto_edge_input_{index}_{length}", plain)
                ct = value(f"crypto_edge_cipher_{index}_{length}", ciphertext)
                add(f"{name} encrypt {length} bytes",
                    f"{operation}_encrypt {src} {k} {raw_options}", ciphertext)
                add(f"{name} decrypt {length} bytes",
                    f"{operation}_decrypt {ct} {k} {raw_options}", plain)

        if iv:
            declarations.extend([
                f"var $crypto_auto_{index} {operation}_encrypt {m} {k} {options};",
                f"var $crypto_auto_hex_{index} hex_encode $crypto_auto_{index};",
                f"var $crypto_open_{index} {operation}_decrypt $crypto_auto_{index} {k} {options};",
                f"var $crypto_open_hex_{index} hex_encode $crypto_open_{index};",
            ])
            automatic.append({
                "name": name,
                "index": index,
                "iv_len": len(iv),
                "encrypted_len": len(iv + encrypted),
                "plaintext": message.hex(),
            })

    for size in (16, 24, 32):
        literal_key = "12345678" * (size // 8)
        iv_bytes = bytes(range(12))
        name = f"aes-{size * 8}-gcm"
        iv_arg = value(f"crypto_literal_iv_{size}", iv_bytes)
        expected = encrypt(name, literal_key.encode(), iv_bytes, b"message")
        for option in ("", f"cipher={name}", f"cipher={name.upper()}"):
            add(name + " literal key " + (option or "default"),
                f"aes_encrypt message {literal_key} {option} iv={iv_arg} format=raw",
                expected)

    # All-zero AES-GCM known answer, including an empty message and no AAD.
    k = value("crypto_zero_key", bytes(16))
    iv = value("crypto_zero_iv", bytes(12))
    add("AES-GCM empty known answer",
        f'aes_encrypt "" {k} iv={iv} format=raw',
        bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"))
    declarations.extend([
        "var $crypto_bad_cipher set rc4;",
        "var $crypto_bad_key set short;",
        "var $crypto_bad_iv set short;",
        "var $crypto_bad_format set other;",
        "var $crypto_bad_padding set other;",
    ])
    add("unsupported dynamic AES cipher",
        "aes_encrypt x $crypto_key_0 cipher=$crypto_bad_cipher", b"")
    add("wrong dynamic key length",
        "aes_encrypt x $crypto_bad_key cipher=aes-128-gcm", b"")
    add("wrong dynamic IV length",
        "aes_encrypt x $crypto_key_0 cipher=aes-128-gcm iv=$crypto_bad_iv", b"")
    add("invalid dynamic format",
        "aes_encrypt x $crypto_key_0 cipher=aes-128-gcm format=$crypto_bad_format", b"")
    add("invalid dynamic padding",
        "aes_encrypt x $crypto_key_0 cipher=aes-128-cbc padding=$crypto_bad_padding", b"")
    add("explicit AES-256 cipher rejects a 128-bit dynamic key",
        "aes_encrypt x $crypto_key_0 cipher=aes-256-gcm", b"")
    add("explicit AES-128 cipher rejects a 256-bit dynamic key",
        "aes_encrypt x $crypto_key_12 cipher=aes-128-gcm", b"")
    declarations.extend([
        "var $crypto_mismatched_cipher set aes-256-gcm;",
        "var $crypto_empty_cipher set \"\";",
    ])
    add("dynamic cipher rejects a mismatched literal key",
        "aes_encrypt x 1234567890123456 cipher=$crypto_mismatched_cipher", b"")
    add("dynamic cipher rejects a mismatched dynamic key",
        "aes_decrypt $crypto_packed_0 $crypto_key_0 cipher=$crypto_mismatched_cipher", b"")
    add("empty dynamic cipher is not a default",
        "aes_encrypt x $crypto_key_0 cipher=$crypto_empty_cipher", b"")
    (root / "cipher-directives.conf").write_text("\n".join(declarations) + "\n")
    (root / "cipher-cases.json").write_text(json.dumps({
        "cases": cases,
        "automatic": automatic,
    }))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
