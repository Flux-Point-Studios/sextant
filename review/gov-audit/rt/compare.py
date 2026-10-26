"""Compare the contract label, my model, Rust and Python on each vector.
DANGER: an implementation reads NO_USE where the label/model says USE_FOUND or
INCOMPLETE. PARITY: Rust and Python disagree; SAFE-SIDE when neither side is
NO_USE unless both are NO_USE."""
import json
import sys

rows = {r["id"]: r for r in json.load(open(sys.argv[1]))}
rust = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(sys.argv[2])}
py = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(sys.argv[3])}
counts = {"danger_rust": 0, "danger_py": 0, "parity": 0, "unsafe_parity": 0, "panic": 0}
print(f"{'id':34s} {'ledger':7s} {'label':28s} {'model':10s} {'rust':10s} {'python':10s} flags")
for id_, r in rows.items():
    lab = r["label"]
    allowed = lab.split(":", 1)[1].split("|") if lab.startswith("AMBIG:") else [lab]
    rv, pv = rust[id_][3], py[id_][3]
    flags = []
    if rv in ("PANIC",) or pv in ("RAISED",):
        counts["panic"] += 1
        flags.append("CRASH")
    must_not_be_no_use = "NO_USE" not in allowed
    if rv == "NO_USE" and must_not_be_no_use:
        counts["danger_rust"] += 1
        flags.append("DANGER-RUST-FALSE-NO_USE")
    if pv == "NO_USE" and must_not_be_no_use:
        counts["danger_py"] += 1
        flags.append("DANGER-PY-FALSE-NO_USE")
    if rv != pv:
        counts["parity"] += 1
        unsafe = (rv == "NO_USE") != (pv == "NO_USE")
        if unsafe:
            counts["unsafe_parity"] += 1
        flags.append("PARITY-" + ("NO_USE-SPLIT" if unsafe else "safe-side"))
    if rv not in allowed:
        flags.append(f"rust!=label")
    if pv not in allowed:
        flags.append(f"py!=label")
    print(f"{id_:34s} {r['ledger']:7s} {lab:28s} {r['model']:10s} {rv:10s} {pv:10s} {' '.join(flags)}")
print(json.dumps(counts))
