"""Classify NO_USE mutants whose target bytes survive, using cbor2 as an independent decoder."""
import io, sys, collections, cbor2

def strict(data):
    """Decode exactly one item; return (obj, trailing_len) or raise."""
    f = io.BytesIO(data)
    obj = cbor2.CBORDecoder(f).decode()
    return obj, len(data) - f.tell()

def paths(obj, needle, path=()):
    out = []
    if isinstance(obj, (bytes, bytearray)):
        i = bytes(obj).find(needle)
        if i >= 0:
            out.append((path, len(obj), i, bytes(obj)[:1].hex()))
    elif isinstance(obj, cbor2.CBORTag):
        out += paths(obj.value, needle, path + (f"tag{obj.tag}",))
    elif isinstance(obj, (set, frozenset)):
        for k, v in enumerate(sorted(obj, key=repr)):
            out += paths(v, needle, path + ("set", k))
    elif isinstance(obj, (list, tuple)):
        for k, v in enumerate(obj):
            out += paths(v, needle, path + (k,))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out += paths(k, needle, path + (f"key:{k!r}"[:40],))
            out += paths(v, needle, path + (k if isinstance(k, int) else "k?",))
    elif isinstance(obj, cbor2.FrozenDict if hasattr(cbor2, 'FrozenDict') else dict):
        pass
    return out

W = {}
def needle_for(seed, tx):
    return None

rows = [l.split() for l in open(sys.argv[1]) if l.strip()]
classes = collections.Counter()
samples = collections.defaultdict(list)
for row in rows:
    seed = row[0]
    split = row[2].split("=")[1] == "true"
    tx = bytes.fromhex(row[3].split("=")[1])
    # target evidence: 28-byte run of a1/a2/a3/a5/a7/a8/ba/bd/be/d0 or a vkey (32 x 0x77 or oracle vkey)
    ev = bytes.fromhex(row[4].split("=")[1])
    if not split:
        try:
            obj, trail = strict(tx)
            cls = f"UNSPLIT first-item={type(obj).__name__} trailing={trail>0}"
        except Exception as e:
            cls = f"UNSPLIT cbor2-rejects({type(e).__name__})"
    else:
        try:
            obj, trail = strict(tx)
            if trail:
                cls = "SPLIT trailing"
            else:
                body, wits = obj[0], obj[1]
                where = [("body",) + p[0] for p in paths(body, ev)] + [("wits",) + p[0] for p in paths(wits, ev)]
                cls = "SPLIT cbor2-ok at " + (";".join("/".join(map(str, w)) for w in where) or "nowhere")
        except Exception as e:
            cls = f"SPLIT cbor2-rejects({type(e).__name__}: {str(e)[:50]})"
    key = f"{cls}"
    classes[key] += 1
    if len(samples[key]) < 2:
        samples[key].append(f"{seed} {tx.hex()[:160]}")
for k, n in classes.most_common():
    print(f"{n:5d}  {k}")
    for s in samples[k]:
        print("         e.g.", s)

print("\n=== covered-prefix paths with an exact typed leaf (would be a genuine miss) ===")
import hashlib
def exact(path, ln, off, hdr):
    p = "/".join(map(str, path))
    if p.startswith("wits/1/") and ln == 28 and off == 0: return "native-sig leaf"
    if p.startswith("body/4/") and ((ln == 28 and off == 0) or (ln == 29 and off == 1)): return "cert leaf"
    if p.startswith("body/14/") and ln == 28 and off == 0: return "required signer"
    if (p.startswith("body/1/") or p.startswith("body/16/")) and p.endswith("/0") and ln >= 29:
        nib = int(hdr, 16) >> 4
        if off == 1 and nib <= 7: return f"output payment nib={nib}"
        if off == 29 and nib <= 3 and ln >= 57: return f"output stake nib={nib}"
    if p.startswith("body/5/") and ln >= 29 and off == 1: return "withdrawal"
    if (p.startswith("wits/0/") or p.startswith("wits/2/")) and p.endswith("/0") and ln == 32 and off == 0: return "vkey"
    if p.startswith("body/19/") and ln == 28 and off == 0: return "voter"
    if p.startswith("body/20/") and ln >= 29 and off == 1: return "proposal reward"
    return None
flag = 0
for row in rows:
    split = row[2].split("=")[1] == "true"
    if not split: continue
    tx = bytes.fromhex(row[3].split("=")[1]); ev = bytes.fromhex(row[4].split("=")[1])
    try:
        obj, trail = strict(tx)
    except Exception:
        continue
    for side, part in (("body", obj[0]), ("wits", obj[1])):
        for (path, ln, off, hdr) in paths(part, ev):
            why = exact((side,) + path, ln, off, hdr)
            if why:
                flag += 1
                print(row[0], why, "/".join(map(str, (side,) + path)), "len", ln, "off", off, tx.hex()[:200])
print("flagged:", flag)
