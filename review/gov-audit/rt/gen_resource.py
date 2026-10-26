import sys
from rtenc import A, M, Raw, Tag, enc, tx, NULL
from gen_extra import W, O, RET, ANCH, DEP, Q, e0, prop

def body_with_action_bytes(action_bytes):
    # proposals = [ [DEP, RET, <action>, ANCH] ] spliced at the byte level
    p = b"\x81" + b"\x84" + enc(DEP) + enc(RET) + action_bytes + enc(ANCH)
    body = b"\xa1\x14" + p
    return b"\x84" + body + b"\xa0\xf5\xf6"

rows = []
# R1: removal set header claims 2^64-1 members; one real member then the add map
r1 = b"\x85\x04\xf6" + b"\x9b" + b"\xff" * 8 + enc([0, W]) + b"\xa0" + enc(Q)
rows.append(("R1_removal_count_u64max_then_W", body_with_action_bytes(r1)))
# R2: prev_id of no_confidence nested 1,000,000 definite arrays deep
depth = 1_000_000
r2 = b"\x82\x03" + b"\x81" * depth + b"\x00"
rows.append(("R2_prev_id_nested_1M_definite", body_with_action_bytes(r2)))
# R3: same with indefinite arrays
r3 = b"\x82\x03" + b"\x9f" * depth + b"\xff" * depth
rows.append(("R3_prev_id_nested_1M_indefinite", body_with_action_bytes(r3)))
# R4: removal set of 200,000 unwatched members then W last
members = [[0, bytes([n % 251, (n >> 8) % 251, (n >> 16) % 251]) + O[3:]] for n in range(200_000)] + [[0, W]]
r4 = enc([4, None, members, {}, Q])
rows.append(("R4_removal_200k_then_W", body_with_action_bytes(r4)))
# R5: treasury map header claims 2^32 entries, nothing follows
r5 = b"\x83\x02" + b"\xba" + b"\xff" * 4
rows.append(("R5_treasury_count_u32max_truncated", body_with_action_bytes(r5)))
# R6: gov_action array header claims 2^64-1 elements with kind 6
r6 = b"\x9b" + b"\xff" * 8 + b"\x06"
rows.append(("R6_action_len_u64max_kind6", body_with_action_bytes(r6)))
with open(sys.argv[1], "w") as f:
    for name, raw in rows:
        f.write(f"{name}\t{raw.hex()}\t{W.hex()}\n")
print("wrote", len(rows), [len(r) for _, r in rows])
