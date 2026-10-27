#!/usr/bin/env python3
"""BENCH.md §2.4 tamper control: flip exactly ONE byte inside a fixture's
`multi_signature` hex.

The flipped byte is chosen inside the cryptographic payload, not the JSON
scaffolding: `multi_signature` is hex-encoded STM signature JSON, and the
target is the last ASCII digit of the FIRST number in the first `"sigma":[...]`
byte array (the first single signature's BLS sigma point). Changing a decimal
digit d -> d-1 (or '0' -> '1') only changes the ASCII byte's low nibble, so
exactly one hex character of the fixture file flips, the string stays valid
hex, the inner JSON stays valid JSON, and the byte value stays <= 255.

Usage: make-tampered.py <fixture.json> <out.tampered.json>
Prints a manifest documenting the offset (goes to run evidence).
"""
import hashlib
import sys


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as f:
        data = f.read()

    key = b'"multi_signature":"'
    ms_start = data.index(key) + len(key)
    ms_end = data.index(b'"', ms_start)
    decoded = bytes.fromhex(data[ms_start:ms_end].decode())

    sig_key = b'"sigma":['
    j = decoded.index(sig_key) + len(sig_key)
    k = j
    while decoded[k] not in b',]':
        k += 1
    d = k - 1  # last ASCII digit of the first sigma byte value
    old = decoded[d]
    assert ord("0") <= old <= ord("9"), "expected an ASCII digit in sigma array"
    new = old + 1 if old == ord("0") else old - 1

    # ASCII digits share high nibble 0x3: only the low-nibble hex char flips.
    off = ms_start + 2 * d + 1
    tampered = bytearray(data)
    old_hex, new_hex = format(old & 0xF, "x"), format(new & 0xF, "x")
    assert chr(tampered[off]) == old_hex, "hex/decoded offset mapping broke"
    tampered[off] = ord(new_hex)

    with open(dst, "wb") as f:
        f.write(tampered)

    print(f"src={src} sha256={hashlib.sha256(data).hexdigest()}")
    print(f"dst={dst} sha256={hashlib.sha256(bytes(tampered)).hexdigest()}")
    print(
        f"file_offset={off} old_char={old_hex} new_char={new_hex} "
        f"(multi_signature hex spans [{ms_start},{ms_end}); decoded sigma byte "
        f"index {d}: {old} -> {new}, i.e. ASCII '{chr(old)}' -> '{chr(new)}')"
    )


if __name__ == "__main__":
    main()
