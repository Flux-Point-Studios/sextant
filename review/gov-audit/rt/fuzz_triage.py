import json, sys
from collections import Counter
from rtcbor import loads, diag
rows = {r["id"]: r for r in json.load(open(sys.argv[1]))}
py = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(sys.argv[2])}

def tags(node, acc):
    k = node[0]
    if k == "tag":
        acc.add(node[1]); tags(node[2], acc)
    elif k == "a":
        for x in node[1]: tags(x, acc)
    elif k == "m":
        for a, b in node[1]: tags(a, acc); tags(b, acc)
    return acc

def dup_keys(node):
    k = node[0]
    if k == "m":
        keys = [repr(a) for a, _ in node[1]]
        if len(keys) != len(set(keys)): return True
        return any(dup_keys(a) or dup_keys(b) for a, b in node[1])
    if k == "a": return any(dup_keys(x) for x in node[1])
    if k == "tag": return dup_keys(node[2])
    return False

for cls in ("FALSE_NO_USE", "EXTRA_USE"):
    cause = Counter(); ex = {}
    for id_, r in rows.items():
        pv = py[id_][3]
        hit = (cls == "FALSE_NO_USE" and pv == "NO_USE" and r["model"] != "NO_USE") or \
              (cls == "EXTRA_USE" and pv == "USE_FOUND" and r["model"] != "USE_FOUND")
        if not hit: continue
        t = tags(loads(bytes.fromhex(r["tx"])), set())
        key = ("tag55799" if 55799 in t else "") + ("+dupkeys" if dup_keys(loads(bytes.fromhex(r["tx"]))) else "")
        key = key or "OTHER:" + ";".join(r["notes"])[:80]
        cause[key] += 1; ex.setdefault(key, id_)
    print(cls, dict(cause))
    for key, id_ in ex.items():
        print("  example", key, id_, "model notes:", rows[id_]["notes"])
