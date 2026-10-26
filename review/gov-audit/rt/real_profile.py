import json
import sys
from collections import Counter
from rtcbor import loads

data = json.load(open(sys.argv[1]))
feat = Counter()
rows = []
ABSENT = bytes([0xEE]) * 28


def creds_of(action, out, feats):
    if action[0] != "a":
        feats["action_not_array"] += 1
        return
    if not action[2]:
        feats["action_indefinite"] += 1
    items = action[1]
    kind = items[0][1] if items and items[0][0] == "u" else None
    feats[f"kind{kind}_arity{len(items)}"] += 1
    def h(node, label):
        if node[0] == "b":
            if not node[2]:
                feats["chunked_hash"] += 1
            if len(node[1]) == 28:
                out.append((label, node[1]))
    if kind == 2:
        m = items[1]
        feats[f"treasury_recipients_{len(m[1])}"] += 1
        if not m[2]:
            feats["treasury_map_indefinite"] += 1
        for k, _ in m[1]:
            feats[f"reward_hdr_{k[1][0]:02x}_len{len(k[1])}"] += 1
            if len(k[1]) == 29:
                out.append(("treasury_recipient", k[1][1:29]))
        h(items[2], "treasury_policy")
    elif kind == 0:
        h(items[3], "param_policy")
    elif kind == 5:
        c = items[2]
        if not c[2]:
            feats["constitution_indefinite"] += 1
        h(c[1][1], "constitution_script")
    elif kind == 4:
        rem, add = items[2], items[3]
        feats["removal_tag" + (str(rem[1]) if rem[0] == "tag" else "none")] += 1
        rem_a = rem[2] if rem[0] == "tag" else rem
        if not rem_a[2]:
            feats["removal_indefinite"] += 1
        feats[f"removal_members_{len(rem_a[1])}"] += 1
        feats[f"added_members_{len(add[1])}"] += 1
        for c in rem_a[1]:
            if not c[2]:
                feats["cred_indefinite"] += 1
            out.append(("committee_removed", c[1][1][1]))
        for c, _ in add[1]:
            if not c[2]:
                feats["cred_indefinite"] += 1
            out.append(("committee_added", c[1][1][1]))
        q = items[4]
        feats["quorum_" + ("tag30" if q[0] == "tag" and q[1] == 30 else "untagged")] += 1


tsv = open(sys.argv[2], "w")
for txh, c in sorted(data.items()):
    raw = bytes.fromhex(c)
    tx = loads(raw)
    body = tx[1][0]
    props = dict((k[1], v) for k, v in body[1])[20]
    feat["proposals_tag258" if props[0] == "tag" else "proposals_untagged"] += 1
    arr = props[2] if props[0] == "tag" else props
    feat[f"proposals_per_tx_{len(arr[1])}"] += 1
    found = []
    for p in arr[1]:
        feat[f"proposal_arity_{len(p[1])}"] += 1
        acct = p[1][1][1]
        feat[f"deposit_hdr_{acct[0]:02x}_len{len(acct)}"] += 1
        creds_of(p[1][2], found, feat)
    tsv.write(f"{txh[:16]}_absent\t{c}\t{ABSENT.hex()}\n")
    seen = set()
    for label, cred in found:
        if cred in seen:
            continue
        seen.add(cred)
        tsv.write(f"{txh[:16]}_{label}\t{c}\t{cred.hex()}\n")
    rows.append((txh, len(found)))
tsv.close()
for k in sorted(feat):
    print(f"{k:32s} {feat[k]}")
print("typed credentials found in real gov_actions:", sum(n for _, n in rows))
