import json
import sys
from rtcbor import loads, diag, find_bytes_paths
from model import evaluate

doc = json.load(open(sys.argv[1]))
W = bytes([0xD1]) * 28
NAMES = {W: "WATCHED", bytes([0xD2]) * 28: "OTHER", bytes([0xD3]) * 28: "OTHER_SCRIPT",
         b"\xe0" + bytes([0xC1]) * 28: "RETURN", b"\xe0" + bytes([0xD1]) * 28: "e0+WATCHED",
         b"\xe0" + bytes([0xD2]) * 28: "e0+OTHER", bytes([0xAA]) * 32: "PRIOR_TXID",
         bytes([0x0B]) * 32: "ANCHOR_HASH"}
rows = []
for v in doc["vectors"]:
    raw = bytes.fromhex(v["raw_tx_hex"])
    target = bytes.fromhex(v["target_vkh"])
    assert target == W, v["name"]
    tx = loads(raw)
    body, wits, valid, aux = tx[1]
    body_keys = [k[1] for k, _ in body[1]]
    proposals = dict((k[1], val) for k, val in body[1])[20]
    paths = find_bytes_paths(tx, W)
    # also look for the watched hash at any byte offset of the raw tx
    raw_hits = [i for i in range(len(raw) - 27) if raw[i:i + 28] == W]
    m = evaluate(raw, target)
    ms = evaluate(raw, target, strict_len=True, two_element_ok=False)
    exp = v["expected"]
    derived = (m["found"], m["complete"], m["verdict"])
    oracle = (exp["use_surfaces"]["target_found"], exp["use_surfaces"]["complete"], exp["verdict"])
    inp_ok = exp["resolved_input"] == {"target_found": False, "complete": True}
    print(f"== {v['name']}")
    print(f"   envelope: array4={tx[0]=='a' and len(tx[1])==4} body_keys={body_keys} wits={diag(wits)} valid={diag(valid)} aux={diag(aux)}")
    print(f"   proposals: {diag(proposals, NAMES)}")
    print(f"   WATCHED paths: {paths}  raw-offset hits: {raw_hits}")
    print(f"   model(non-strict)={derived} notes={m['notes']}  model(strict)={(ms['found'], ms['complete'], ms['verdict'])}")
    print(f"   oracle={oracle} resolved_input_expected_clean={inp_ok}  AGREE={derived == oracle}")
    rows.append((v["name"], derived, oracle, derived == oracle, (ms['found'], ms['complete'], ms['verdict'])))
print()
print("SUMMARY")
for name, d, o, ok, st in rows:
    print(f"{name:36s} derived={d[2]:10s} oracle={o[2]:10s} found/complete d={d[:2]} o={o[:2]} agree={ok} strict={st[2]}")
