"""Hand-assembled minimal vectors (raw bytes, no shared encoder)."""
W = bytes([0xD1]) * 28
O = bytes([0xD2]) * 28
RET = b"\x58\x1d\xe0" + bytes([0xC1]) * 28            # bytes(29) deposit-return account
ANCHOR = b"\x82\x60\x58\x20" + bytes([0x0B]) * 32       # ["", h32]
def acct(hdr, cred): return b"\x58\x1d" + bytes([hdr]) + cred
def proposal(action): return b"\x84\x18\x64" + RET + action + ANCHOR
def txn(proposals_array): return b"\x84" + b"\xa1\x14" + proposals_array + b"\xa0\xf5\xf6"
VECTORS = {
    # treasury {e0+O: 1, e0+W: 2}, nil -- watched key is the 2nd recipient
    "min_treasury_2nd": txn(b"\x81" + proposal(b"\x83\x02\xa2" + acct(0xE0, O) + b"\x01" + acct(0xE0, W) + b"\x02\xf6")),
    # treasury {e1+W: 1}, nil -- mainnet key-hash reward account header
    "min_treasury_e1": txn(b"\x81" + proposal(b"\x83\x02\xa1" + acct(0xE1, W) + b"\x01\xf6")),
    # [info] then [treasury {e0+W: 1}, nil] -- watched key in the 2nd proposal
    "min_second_proposal": txn(b"\x82" + proposal(b"\x81\x06") + proposal(b"\x83\x02\xa1" + acct(0xE0, W) + b"\x01\xf6")),
    # update_committee removing [[0,O],[0,W]] -- watched key is the 2nd removed member
    "min_removed_2nd": txn(b"\x81" + proposal(b"\x85\x04\xf6\x82\x82\x00\x58\x1c" + O + b"\x82\x00\x58\x1c" + W + b"\xa0\xd8\x1e\x82\x01\x02")),
    # update_committee adding {[0,O]: 1, [0,W]: 2} -- watched key is the 2nd added member
    "min_added_2nd": txn(b"\x81" + proposal(b"\x85\x04\xf6\x80\xa2\x82\x00\x58\x1c" + O + b"\x01\x82\x00\x58\x1c" + W + b"\x02\xd8\x1e\x82\x01\x02")),
}
if __name__ == "__main__":
    import sys
    with open(sys.argv[1], "w") as f:
        for k, v in VECTORS.items():
            f.write(f"{k}\t{v.hex()}\t{W.hex()}\n")
    print("\n".join(f"{k} {len(v)}B" for k, v in VECTORS.items()))
