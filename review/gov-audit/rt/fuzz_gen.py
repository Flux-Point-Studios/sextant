"""Randomized gov_action differential cases (seeded). Writes TSV + JSON with my
model's contract verdict for each. Mutations: indefinite toggles, chunked
hashes, foreign tags on sets, wrong-typed typed positions, arity +/-1,
duplicates, header variants, multi-proposal sets."""
import json
import random
import sys
from rtenc import A, B, M, Neg, Raw, T, Tag, U, NULL, UNDEF, TRUE, enc, tx
from model import evaluate

W = bytes([0xD1]) * 28
ANCH = ["https://example.invalid/p", bytes([0x0B]) * 32]
RET = b"\xe0" + bytes([0xC1]) * 28


def h28(rng, p_w):
    return W if rng.random() < p_w else bytes([rng.randrange(256)]) + bytes(rng.randrange(256) for _ in range(27))


def maybe_chunk(rng, raw):
    if rng.random() < 0.08 and len(raw) > 2:
        cut = rng.randrange(1, len(raw))
        return B(raw, chunks=[cut, len(raw) - cut])
    return raw


def bad_value(rng):
    return rng.choice([5, T("x"), NULL, UNDEF, TRUE, b"\x01" * 27, b"\x01" * 29, [], {}, Tag(259, []), Neg(-3)])


def cred(rng, p_w):
    c = [rng.choice([0, 1]), maybe_chunk(rng, h28(rng, p_w))]
    r = rng.random()
    if r < 0.05:
        return A(c, indef=True)
    if r < 0.08:
        return [rng.choice([2, 7]), c[1]]
    if r < 0.10:
        return bad_value(rng)
    return c


def a_set(rng, items):
    s = A(items, indef=rng.random() < 0.2)
    r = rng.random()
    if r < 0.4:
        return Tag(258, s)
    if r < 0.46:
        return Tag(rng.choice([259, 24, 55799, 30]), s)
    return s


def a_map(rng, pairs):
    if rng.random() < 0.06 and pairs:
        pairs = pairs + [pairs[0]]
    m = M(pairs, indef=rng.random() < 0.2)
    if rng.random() < 0.04:
        return Tag(rng.choice([258, 259]), m)
    return m


def policy(rng, p_w):
    r = rng.random()
    if r < 0.45:
        return None
    if r < 0.93:
        return maybe_chunk(rng, h28(rng, p_w))
    return bad_value(rng)


def prev(rng):
    return None if rng.random() < 0.5 else [bytes([0xAA]) * 32, rng.randrange(3)]


def action(rng, p_w):
    kind = rng.choice([0, 1, 2, 3, 4, 5, 6] * 6 + [7, 9, 2**64 - 1])
    if kind == 0:
        items = [0, prev(rng), {0: 44}, policy(rng, p_w)]
    elif kind == 1:
        items = [1, prev(rng), [10, 0]]
    elif kind == 2:
        pairs = []
        for _ in range(rng.randrange(4)):
            hdr = rng.choice([b"\xe0", b"\xe1", b"\xf0", b"\xf1"])
            key = maybe_chunk(rng, hdr + h28(rng, p_w)) if rng.random() > 0.05 else bad_value(rng)
            pairs.append((key, rng.randrange(1, 10**9)))
        items = [2, a_map(rng, pairs), policy(rng, p_w)]
    elif kind == 3:
        items = [3, prev(rng)]
    elif kind == 4:
        rem = [cred(rng, p_w) for _ in range(rng.randrange(4))]
        add = [(cred(rng, p_w), rng.randrange(1000)) for _ in range(rng.randrange(4))]
        items = [4, prev(rng), a_set(rng, rem), a_map(rng, add), Tag(30, [1, 2])]
    elif kind == 5:
        c = [ANCH, policy(rng, p_w)]
        r = rng.random()
        cons = A(c, indef=True) if r < 0.1 else ([ANCH, None, None] if r < 0.14 else c)
        items = [5, prev(rng), cons]
    elif kind == 6:
        items = [6]
    else:
        items = [U(kind) if kind >= 0 else kind, None, cred(rng, p_w)]
    r = rng.random()
    if r < 0.05:
        items = items + [None]
    elif r < 0.10 and len(items) > 1:
        items = items[:-1]
    elif r < 0.13:
        items[0] = bad_value(rng)
    return A(items, indef=rng.random() < 0.08)


def proposals(rng, p_w):
    ps = [[100, maybe_chunk(rng, RET), action(rng, p_w), ANCH] for _ in range(rng.randrange(1, 4))]
    s = A(ps, indef=rng.random() < 0.15)
    return Tag(258, s) if rng.random() < 0.4 else s


def main(n, seed, out_json, out_tsv):
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        p_w = rng.choice([0.0, 0.15, 0.4])
        raw = tx([(20, proposals(rng, p_w))])
        m = evaluate(raw, W)
        rows.append({"id": f"F{i:05d}", "tx": raw.hex(), "model": m["verdict"], "notes": m["notes"]})
    json.dump(rows, open(out_json, "w"))
    with open(out_tsv, "w") as f:
        for r in rows:
            f.write(f"{r['id']}\t{r['tx']}\t{W.hex()}\n")
    from collections import Counter
    print(n, "cases", Counter(r["model"] for r in rows))


if __name__ == "__main__":
    main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4])
