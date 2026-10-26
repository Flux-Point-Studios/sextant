"""Independent, encoding-preserving CBOR decoder for the red-team audit.

Not cbor2: every node keeps whether it was definite, chunked or tagged, so a
vector's real wire shape can be checked rather than its normalized value.
Nodes: ('u', n) ('n', n) ('b', bytes, definite, nchunks) ('t', str, definite)
('a', [items], definite) ('m', [(k, v)], definite) ('tag', n, item)
('s', name) ('f', value). Each node is a tuple; raises ValueError on bad input.
"""
import struct

MAX_DEPTH = 2000


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def byte(self):
        if self.i >= len(self.d):
            raise ValueError("eof")
        b = self.d[self.i]
        self.i += 1
        return b

    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError("eof")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def arg(self, ai):
        if ai < 24:
            return ai
        if ai == 24:
            return self.byte()
        if ai == 25:
            return int.from_bytes(self.take(2), "big")
        if ai == 26:
            return int.from_bytes(self.take(4), "big")
        if ai == 27:
            return int.from_bytes(self.take(8), "big")
        raise ValueError(f"bad additional info {ai}")

    def item(self, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("too deep")
        ib = self.byte()
        mt, ai = ib >> 5, ib & 0x1F
        if mt == 0:
            return ("u", self.arg(ai))
        if mt == 1:
            return ("n", -1 - self.arg(ai))
        if mt in (2, 3):
            if ai == 31:
                chunks = []
                while True:
                    nb = self.byte()
                    if nb == 0xFF:
                        break
                    if nb >> 5 != mt or (nb & 0x1F) == 31:
                        raise ValueError("bad chunk")
                    chunks.append(self.take(self.arg(nb & 0x1F)))
                raw = b"".join(chunks)
                return ("b", raw, False, len(chunks)) if mt == 2 else ("t", raw.decode(), False)
            raw = self.take(self.arg(ai))
            return ("b", raw, True, 1) if mt == 2 else ("t", raw.decode(), True)
        if mt == 4:
            if ai == 31:
                items = []
                while self.d[self.i] != 0xFF:
                    items.append(self.item(depth + 1))
                self.i += 1
                return ("a", items, False)
            return ("a", [self.item(depth + 1) for _ in range(self.arg(ai))], True)
        if mt == 5:
            if ai == 31:
                pairs = []
                while self.d[self.i] != 0xFF:
                    k = self.item(depth + 1)
                    pairs.append((k, self.item(depth + 1)))
                self.i += 1
                return ("m", pairs, False)
            n = self.arg(ai)
            pairs = []
            for _ in range(n):
                k = self.item(depth + 1)
                pairs.append((k, self.item(depth + 1)))
            return ("m", pairs, True)
        if mt == 6:
            return ("tag", self.arg(ai), self.item(depth + 1))
        if ai == 20:
            return ("s", "false")
        if ai == 21:
            return ("s", "true")
        if ai == 22:
            return ("s", "null")
        if ai == 23:
            return ("s", "undefined")
        if ai == 24:
            return ("s", f"simple({self.byte()})")
        if ai == 25:
            return ("f", "f16:" + self.take(2).hex())
        if ai == 26:
            return ("f", struct.unpack(">f", self.take(4))[0])
        if ai == 27:
            return ("f", struct.unpack(">d", self.take(8))[0])
        if ai == 31:
            raise ValueError("unexpected break")
        return ("s", f"simple({ai})")


def loads(data):
    r = Reader(data)
    node = r.item()
    if r.i != len(data):
        raise ValueError(f"trailing {len(data) - r.i} bytes")
    return node


def diag(node, names=None):
    names = names or {}
    k = node[0]
    if k in ("u", "n"):
        return str(node[1])
    if k == "b":
        h = node[1].hex()
        label = names.get(node[1])
        body = f"h'{h[:8]}..'({len(node[1])}B{'=' + label if label else ''})" if len(node[1]) > 8 else f"h'{h}'"
        return body if node[2] else f"(_ chunked x{node[3]} {body})"
    if k == "t":
        return repr(node[1]) if node[2] else f"(_ {node[1]!r})"
    if k == "a":
        inner = ", ".join(diag(x, names) for x in node[1])
        return f"[{inner}]" if node[2] else f"[_ {inner}]"
    if k == "m":
        inner = ", ".join(f"{diag(a, names)}: {diag(b, names)}" for a, b in node[1])
        return f"{{{inner}}}" if node[2] else f"{{_ {inner}}}"
    if k == "tag":
        return f"{node[1]}({diag(node[2], names)})"
    return str(node[1])


def find_bytes_paths(node, needle, path="$"):
    """Every structural path where `needle` occurs inside a byte string leaf."""
    out = []
    k = node[0]
    if k == "b":
        if needle in node[1]:
            out.append((path, len(node[1]), node[1].index(needle)))
    elif k == "a":
        for i, x in enumerate(node[1]):
            out += find_bytes_paths(x, needle, f"{path}[{i}]")
    elif k == "m":
        for i, (a, b) in enumerate(node[1]):
            out += find_bytes_paths(a, needle, f"{path}{{key#{i}}}")
            out += find_bytes_paths(b, needle, f"{path}{{val#{i}}}")
    elif k == "tag":
        out += find_bytes_paths(node[2], needle, f"{path}<tag{node[1]}>")
    return out
