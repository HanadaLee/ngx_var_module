#!/usr/bin/env python3
"""Generate RSA fixtures and independently check nginx results."""

import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def digest(name):
    return {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
            "sha384": hashes.SHA384, "sha512": hashes.SHA512}[name]()


def scheme(case):
    md = digest(case.get("hash", "sha256"))
    mgf = padding.MGF1(digest(case.get("mgf1", case.get("hash", "sha256"))))
    if case["kind"] == "encrypt":
        return padding.OAEP(mgf, md, bytes.fromhex(case.get("label", "")))
    if case.get("padding", "pss") == "pkcs1":
        return padding.PKCS1v15()
    return padding.PSS(mgf, case.get("salt", md.digest_size))


def generate(root):
    declarations, cases = [], []
    keys = {}
    for name, bits in (("one", 2048), ("two", 2048), ("large", 3072)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        keys[name] = key
        private = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        (root / f"rsa-{name}.pem").write_bytes(private)
        (root / f"rsa-{name}.pub").write_bytes(public)
        (root / f"rsa-{name}.pem").chmod(0o600)
        declarations.extend([
            f'var $rsa_private_{name} set "{private.decode().replace(chr(10), chr(92)+"n")}";',
            f'var $rsa_public_{name} set "{public.decode().replace(chr(10), chr(92)+"n")}";',
        ])
    encrypted = keys["one"].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test-password"))
    (root / "rsa-encrypted.pem").write_bytes(encrypted)
    (root / "rsa-encrypted.pem").chmod(0o600)
    traditional = keys["one"].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    (root / "rsa-traditional.pem").write_bytes(traditional)
    (root / "rsa-traditional.pem").chmod(0o600)
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (root / "rsa-wrong-type.pub").write_bytes(other)

    def binary(name, data):
        if data:
            declarations.append(f"var ${name} hex_decode {data.hex()};")
        else:
            declarations.append(f'var ${name} set "";')
        return "$" + name

    def add(name, expression, expected=None, **reference):
        index = len(cases)
        declarations.append(f"var $rsa_result_{index} {expression};")
        if expression.startswith("rsa_verify "):
            variable = f"$rsa_result_{index}"
        else:
            declarations.append(f"var $rsa_hex_{index} hex_encode $rsa_result_{index};")
            variable = f"$rsa_hex_{index}"
        cases.append(dict(name=name, variable=variable, expected=expected, **reference))

    message = b"rsa\x00message\xff"
    m = binary("rsa_message", message)
    label = b"tenant\x00one"
    l = binary("rsa_label", label)
    declarations += ['var $rsa_password set test-password;',
                     'var $rsa_bad_password set incorrect;',
                     'var $rsa_bad_key set invalid;',
                     'var $rsa_bad_hash set md5;',
                     'var $rsa_bad_padding set none;',
                     'var $rsa_bad_salt set -2;',
                     'var $rsa_key_file set rsa-one.pub;']

    for md in ("sha1", "sha256", "sha384", "sha512"):
        ref = dict(kind="encrypt", key="one", hash=md, label=label.hex(), message=message.hex())
        ct = keys["one"].public_key().encrypt(message, scheme(ref))
        c = binary(f"rsa_cipher_{md}", ct)
        opts = f"oaep_hash={md} label={l}"
        add(f"OAEP {md} decrypt", f"rsa_decrypt {c} rsa-one.pem {opts}", message.hex())
        add(f"OAEP {md} encrypt", f"rsa_encrypt {m} rsa-one.pub {opts}", **ref)
        add(f"OAEP {md} wrong label", f"rsa_decrypt {c} rsa-one.pem oaep_hash={md}", "")
        add(f"OAEP {md} wrong key", f"rsa_decrypt {c} rsa-two.pem {opts}", "")
        for pad in ("pss", "pkcs1"):
            ref = dict(kind="sign", key="one", hash=md, padding=pad, message=message.hex())
            sig = keys["one"].sign(message, scheme(ref), digest(md))
            v = binary(f"rsa_signature_{pad}_{md}", sig)
            opts = f"padding={pad} hash={md}"
            add(f"{pad} {md} verify", f"rsa_verify {m} rsa-one.pub {v} {opts}", "1")
            add(f"{pad} {md} altered message", f"rsa_verify altered rsa-one.pub {v} {opts}", "0")
            add(f"{pad} {md} wrong key", f"rsa_verify {m} rsa-two.pub {v} {opts}", "0")
            add(f"{pad} {md} sign", f"rsa_sign {m} rsa-one.pem {opts}",
                sig.hex() if pad == "pkcs1" else None, **ref)

    for name, bits in (("one", 2048), ("large", 3072)):
        max_length = bits // 8 - 2 * 32 - 2
        for length in (0, max_length):
            data = b"x" * length
            value = binary(f"rsa_boundary_{name}_{length}", data)
            ref = dict(kind="encrypt", key=name, message=data.hex())
            add(f"{bits}-bit OAEP encrypt {length} bytes",
                f"rsa_encrypt {value} rsa-{name}.pub", **ref)
            ciphertext = binary(f"rsa_boundary_cipher_{name}_{length}",
                                keys[name].public_key().encrypt(data, scheme(ref)))
            add(f"{bits}-bit OAEP decrypt {length} bytes",
                f"rsa_decrypt {ciphertext} rsa-{name}.pem", data.hex())
        excess = binary(f"rsa_excess_{name}", b"x" * (max_length + 1))
        add(f"{bits}-bit OAEP rejects oversized input", f"rsa_encrypt {excess} rsa-{name}.pub", "")
        ref = dict(kind="sign", key=name, message="")
        sig = binary(f"rsa_empty_signature_{name}", keys[name].sign(b"", scheme(ref), hashes.SHA256()))
        add(f"{bits}-bit default PSS sign empty", f'rsa_sign "" rsa-{name}.pem', **ref)
        add(f"{bits}-bit default PSS verify empty", f'rsa_verify "" rsa-{name}.pub {sig}', "1")

    ref = dict(kind="sign", key="one", message=message.hex(), mgf1="sha1", salt=8)
    sig = binary("rsa_custom_signature", keys["one"].sign(message, scheme(ref), hashes.SHA256()))
    add("PSS custom MGF1 and salt sign", f"rsa_sign {m} rsa-one.pem mgf1_hash=sha1 salt_length=8", **ref)
    add("PSS custom MGF1 and salt verify", f"rsa_verify {m} rsa-one.pub {sig} mgf1_hash=sha1 salt_length=8", "1")
    add("PSS automatic salt verify", f"rsa_verify {m} rsa-one.pub {sig} mgf1_hash=sha1 salt_length=auto", "1")
    add("PSS strict salt mismatch", f"rsa_verify {m} rsa-one.pub {sig} mgf1_hash=sha1", "0")
    add("PSS zero salt sign", f"rsa_sign {m} rsa-one.pem salt_length=0",
        kind="sign", key="one", message=message.hex(), salt=0)
    ref = dict(kind="encrypt", key="one", message=message.hex(), mgf1="sha1")
    ct = binary("rsa_custom_cipher", keys["one"].public_key().encrypt(message, scheme(ref)))
    add("OAEP custom MGF1 encrypt", f"rsa_encrypt {m} rsa-one.pub mgf1_hash=sha1", **ref)
    add("OAEP custom MGF1 decrypt", f"rsa_decrypt {ct} rsa-one.pem mgf1_hash=sha1", message.hex())
    add("OAEP MGF1 mismatch", f"rsa_decrypt {ct} rsa-one.pem", "")
    add("dynamic public PEM", f"rsa_encrypt {m} data:$rsa_public_one", kind="encrypt", key="one", message=message.hex())
    add("dynamic public file", f"rsa_encrypt {m} $rsa_key_file", kind="encrypt", key="one", message=message.hex())
    add("dynamic private PEM", f"rsa_sign {m} data:$rsa_private_one", kind="sign", key="one", message=message.hex())
    add("encrypted private key", f"rsa_sign {m} rsa-encrypted.pem password=test-password", kind="sign", key="one", message=message.hex())
    add("dynamic private key password", f"rsa_sign {m} rsa-encrypted.pem password=$rsa_password", kind="sign", key="one", message=message.hex())
    add("wrong private key password", f"rsa_sign {m} rsa-encrypted.pem password=$rsa_bad_password", "")
    add("traditional private key", f"rsa_sign {m} rsa-traditional.pem", kind="sign", key="one", message=message.hex())
    inline_public = (root / 'rsa-one.pub').read_text().replace('\n', '\\n')
    inline_private = (root / 'rsa-one.pem').read_text().replace('\n', '\\n')
    add("static inline public PEM", f'rsa_encrypt {m} "data:{inline_public}"',
        kind="encrypt", key="one", message=message.hex())
    add("static inline private PEM", f'rsa_sign {m} "data:{inline_private}"',
        kind="sign", key="one", message=message.hex())
    for extra, name in (("hash=$rsa_bad_hash", "hash"), ("padding=$rsa_bad_padding", "padding"),
                        ("salt_length=$rsa_bad_salt", "salt length")):
        add("invalid runtime verification " + name, f"rsa_verify {m} rsa-one.pub {sig} {extra}", "0")
    add("invalid runtime verification key", f"rsa_verify {m} $rsa_bad_key {sig}", "0")
    add("invalid runtime signing key", f"rsa_sign {m} $rsa_bad_key", "")
    add("empty signature", f'rsa_verify {m} rsa-one.pub ""', "0")
    add("short signature", f"rsa_verify {m} rsa-one.pub short", "0")
    add("short ciphertext", "rsa_decrypt short rsa-one.pem", "")
    invalid = binary("rsa_invalid_cipher", bytes(256))
    add("invalid OAEP ciphertext", f"rsa_decrypt {invalid} rsa-one.pem", "")

    (root / "rsa-directives.conf").write_text("\n".join(declarations) + "\n")
    (root / "rsa-cases.json").write_text(json.dumps(cases))


def check(root, results, destination):
    cases = json.loads((root / "rsa-cases.json").read_text())
    values = json.loads(Path(results).read_text())
    keys = {}
    checks = []
    for index, case in enumerate(cases):
        try:
            actual = values[index]
            if case["expected"] is not None:
                assert actual == case["expected"], f"got {actual!r}, expected {case['expected']!r}"
            else:
                name = case["key"]
                if name not in keys:
                    keys[name] = serialization.load_pem_private_key((root / f"rsa-{name}.pem").read_bytes(), None)
                data = bytes.fromhex(actual)
                message = bytes.fromhex(case["message"])
                if case["kind"] == "encrypt":
                    assert keys[name].decrypt(data, scheme(case)) == message
                else:
                    keys[name].public_key().verify(data, message, scheme(case), digest(case.get("hash", "sha256")))
            checks.append(dict(ok=True))
        except Exception as exc:
            checks.append(dict(ok=False, error=f"{type(exc).__name__}: {exc}"))
    Path(destination).write_text(json.dumps(checks))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        generate(Path(sys.argv[1]))
    else:
        check(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
