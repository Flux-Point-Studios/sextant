import json, sys
from collections import Counter
rows = {r["id"]: r for r in json.load(open(sys.argv[1]))}
rust = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(sys.argv[2])}
py = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(sys.argv[3])}
c = Counter()
examples = {}
for id_, r in rows.items():
    m, rv, pv = r["model"], rust[id_][3], py[id_][3]
    c[f"rust={rv} model={m}"] += 1
    c[f"py={pv} model={m}"] += 1
    for side, val in (("rust", rv), ("py", pv)):
        if val in ("PANIC", "RAISED"):
            c[f"{side}_CRASH"] += 1; examples.setdefault(f"{side}_CRASH", id_)
        if val == "NO_USE" and m != "NO_USE":
            c[f"{side}_FALSE_NO_USE"] += 1; examples.setdefault(f"{side}_FALSE_NO_USE:{m}", id_)
        if val == "USE_FOUND" and m != "USE_FOUND":
            c[f"{side}_EXTRA_USE"] += 1; examples.setdefault(f"{side}_EXTRA_USE:{m}", id_)
    if rv != pv:
        split = (rv == "NO_USE") != (pv == "NO_USE")
        c["parity_split_no_use" if split else "parity_safe_side"] += 1
        if split: examples.setdefault(f"split rust={rv} py={pv}", id_)
for k in sorted(c): print(f"{k:40s} {c[k]}")
print("examples:", json.dumps(examples, indent=1))
