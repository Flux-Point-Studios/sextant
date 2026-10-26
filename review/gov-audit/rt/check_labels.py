import json, sys
rows = json.load(open(sys.argv[1]))
bad = 0
for r in rows:
    lab = r["label"]
    allowed = lab.split(":", 1)[1].split("|") if lab.startswith("AMBIG:") else [lab]
    ok = r["model"] in allowed
    if not ok:
        bad += 1
        print("LABEL/MODEL MISMATCH", r["id"], "label", lab, "model", r["model"], r["model_notes"])
print("checked", len(rows), "mismatches", bad)
