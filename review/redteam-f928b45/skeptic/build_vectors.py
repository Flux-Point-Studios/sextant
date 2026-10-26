"""Skeptic: rebuild every claimed exploit with cbor2 (independent of the Rust helpers)."""
import json, hashlib, zlib, cbor2
from cbor2 import CBORTag, dumps

W = bytes([0x5a]) * 28            # a fresh watched key hash, not the PoC constant
S = bytes([0x6b]) * 28            # a fresh watched script hash
O = bytes([0x3c]) * 28
TX = bytes([0x7e]) * 32
VK = bytes([0x4f]) * 32
def h224(b): return hashlib.blake2b(b, digest_size=28).digest()

def body(extra=None, outputs=None):
    b = {0: CBORTag(258, [[TX, 0]]), 1: outputs or [{0: b"\x60" + O, 1: 2_000_000}], 2: 180_000}
    b.update(extra or {})
    return dumps(b)
WITS = dumps({0: CBORTag(258, [[VK, bytes(64)]])})
RES = {f"{TX.hex()}#0": (b"\x60" + O).hex()}
anchor = ["https://a.example", bytes(32)]
def prop(action, ret=b"\xe0" + O): return {20: CBORTag(258, [[100_000_000_000, ret, action, anchor]])}

V = []
def add(name, claim, b, w, expect, watched, valid=True, res=None):
    V.append(dict(name=name, claim=claim, body=b.hex(), wits=w.hex(), valid=valid,
                  watched=watched.hex(), resolve=res if res is not None else RES, expect=expect))

# H1 governance
add("H1 update_committee add", "H1", body(prop([4, None, CBORTag(258, []), {(0, W): 500}, CBORTag(30, [2, 3])])), WITS, "NoUse", W)
add("H1 update_committee remove", "H1", body(prop([4, None, CBORTag(258, [[0, W]]), {}, CBORTag(30, [2, 3])])), WITS, "NoUse", W)
add("H1 control deposit-return", "control", body(prop([6], ret=b"\xe0" + W)), WITS, "UseFound", W)
add("H1 control cert-14 cold", "control", body({4: CBORTag(258, [[14, [0, W], [0, O]]])}), WITS, "UseFound", W)
add("H1 treasury withdrawal", "H1", body(prop([2, {b"\xe0" + W: 5}, None])), WITS, "NoUse", W)
add("H1 control body-5 withdrawal", "control", body({5: {b"\xe0" + W: 0}}), WITS, "UseFound", W)
add("H1 guardrail parameter_change", "H1", body(prop([0, None, {0: 44}, S])), WITS, "NoUse", S)
add("H1 guardrail new_constitution", "H1", body(prop([5, None, [anchor, S]])), WITS, "NoUse", S)
add("H1 control script withdrawal", "control", body({5: {b"\xf0" + S: 0}}), WITS, "UseFound", S)
# H2 mint
native = [0, O]
P = h224(b"\x00" + dumps(native))
mint_w = dumps({0: CBORTag(258, [[VK, bytes(64)]]), 1: CBORTag(258, [native])})
add("H2 mint under watched native policy", "H2", body({9: {P: {b"tok": 1}}}), mint_w, "NoUse", P)
add("H2 control spend from policy script address", "control", body(), mint_w, "UseFound", P,
    res={f"{TX.hex()}#0": (b"\x70" + P).hex()})
add("H2 output multiasset policy", "H2-note", body(outputs=[{0: b"\x60" + O, 1: [2_000_000, {P: {b"tok": 1}}]}]), WITS, "NoUse", P)
# unsplittable blob
tx = dumps([cbor2.loads(body(outputs=[{0: b"\x60" + W, 1: 1}])), cbor2.loads(WITS), True, None])
blob = b"\xa0" + tx
add("L whole blob a0||tx", "whole-blob", blob, blob, "NoUse", W)
add("L control whole tx (array)", "control", tx, tx, "Incomplete", W)
# malformed (raw bytes): body map(3) with fee = break
raw = bytearray(body())
mal = bytes([0xa3]) + raw[1:raw.rfind(b"\x02\x1a")] + b"\x02\xff"
add("L fee=break", "malformed", mal, WITS, "NoUse", W)
add("L control fee=indef-unterminated", "control", bytes([0xa3]) + raw[1:raw.rfind(b"\x02\x1a")] + b"\x02\x9f", WITS, "Incomplete", W)
# unknown witness / output keys
add("L unknown witness key 8", "unknown-key", body(), dumps({0: CBORTag(258, [[VK, bytes(64)]]), 8: [[0, W]]}), "NoUse", W)
add("L control unknown body key 23", "control", body({23: [[0, W]]}), WITS, "Incomplete", W)
add("L unknown output key 4", "unknown-key", body(outputs=[{0: b"\x60" + O, 1: 1, 4: [0, W]}]), WITS, "NoUse", W)
# invalid address header
add("L output header 0xd8", "malformed-addr", body(outputs=[[b"\xd8" + W, 1]]), WITS, "NoUse", W)
add("L control output header 0x60", "control", body(outputs=[[b"\x60" + W, 1]]), WITS, "UseFound", W)
# byron
payload = dumps([W, {}, 0])
byron = dumps([CBORTag(24, payload), zlib.crc32(payload)])
add("L byron output root", "byron", body(outputs=[[byron, 1]]), WITS, "NoUse", W)
add("L control byron spent input", "control", body(), WITS, "Incomplete", W, res={f"{TX.hex()}#0": byron.hex()})
# plutus ref trailing
plutus_trailing = bytes([0x82, 0x02, 0x41, 0x00]) + dumps([0, W])
add("L plutus ref trailing sig", "plutus-trailing", body(outputs=[{0: b"\x60" + O, 1: 1, 3: CBORTag(24, plutus_trailing)}]), WITS, "NoUse", W)
add("L control native ref trailing", "control", body(outputs=[{0: b"\x60" + O, 1: 1, 3: CBORTag(24, dumps([0, [0, O]]) + b"\x00")}]), WITS, "Incomplete", W)
json.dump(V, open("/tmp/claude-1000/-home-deci/93582ed9-742f-45d3-9e79-74b6bf1ef9fa/scratchpad/skeptic/vectors.json", "w"), indent=1)
print(len(V), "vectors")
