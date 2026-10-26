"""Byte-exact CBOR encoder for hostile vectors: forced integer widths, chunked
byte strings, indefinite arrays/maps, duplicate map keys, arbitrary tags."""


class U:
    def __init__(self, n, width=None):
        self.n, self.width = n, width


class Neg:
    def __init__(self, n):
        self.n = n


class B:
    def __init__(self, data, chunks=None, width=None):
        self.data, self.chunks, self.width = bytes(data), chunks, width


class T:
    def __init__(self, s):
        self.s = s


class A:
    def __init__(self, items, indef=False, width=None):
        self.items, self.indef, self.width = list(items), indef, width


class M:
    def __init__(self, pairs, indef=False):
        self.pairs, self.indef = list(pairs), indef


class Tag:
    def __init__(self, n, item):
        self.n, self.item = n, item


class Raw:
    def __init__(self, data):
        self.data = bytes(data)


NULL, UNDEF, TRUE, FALSE = Raw(b"\xf6"), Raw(b"\xf7"), Raw(b"\xf5"), Raw(b"\xf4")


def head(major, n, width=None):
    if width is None:
        width = 0 if n < 24 else 1 if n < 256 else 2 if n < 65536 else 4 if n < 2**32 else 8
    if width == 0:
        return bytes([major << 5 | n])
    ai = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([major << 5 | ai]) + n.to_bytes(width, "big")


def enc(x):
    if isinstance(x, Raw):
        return x.data
    if isinstance(x, bool):
        return b"\xf5" if x else b"\xf4"
    if x is None:
        return b"\xf6"
    if isinstance(x, int):
        return head(0, x) if x >= 0 else head(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return head(2, len(x)) + bytes(x)
    if isinstance(x, str):
        raw = x.encode()
        return head(3, len(raw)) + raw
    if isinstance(x, list):
        return enc(A(x))
    if isinstance(x, dict):
        return enc(M(list(x.items())))
    if isinstance(x, U):
        return head(0, x.n, x.width)
    if isinstance(x, Neg):
        return head(1, -1 - x.n)
    if isinstance(x, B):
        if x.chunks is None:
            return head(2, len(x.data), x.width) + x.data
        out, i = b"\x5f", 0
        for size in x.chunks:
            out += head(2, size) + x.data[i:i + size]
            i += size
        assert i == len(x.data)
        return out + b"\xff"
    if isinstance(x, T):
        return enc(x.s)
    if isinstance(x, A):
        body = b"".join(enc(i) for i in x.items)
        return (b"\x9f" + body + b"\xff") if x.indef else head(4, len(x.items), x.width) + body
    if isinstance(x, M):
        body = b"".join(enc(k) + enc(v) for k, v in x.pairs)
        return (b"\xbf" + body + b"\xff") if x.indef else head(5, len(x.pairs)) + body
    if isinstance(x, Tag):
        return head(6, x.n) + enc(x.item)
    raise TypeError(type(x))


def tx(body_pairs, wits=None):
    """[body, witness_set, true, null] with an exact body map."""
    return enc(A([M(body_pairs), M(wits or []), TRUE, NULL]))
