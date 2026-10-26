"""Extra red-team vectors. Each: (id, category, ledger, label, body_pairs).
ledger: 'valid' (decodes under the Conway ledger at PV9-11), 'pv12' (valid only
from PV12, chunked bytes), 'rule' (decodes; a phase-1 GOV rule rejects),
'invalid' (ledger decoder rejects). label: the contract verdict I assign by hand
(USE_FOUND / NO_USE / INCOMPLETE), or 'AMBIG:<a>|<b>' when the contract does not
decide a ledger-invalid shape."""
import json
import sys
from rtenc import A, B, M, Neg, Raw, T, Tag, U, NULL, UNDEF, TRUE, enc, tx
from model import evaluate

W, O, OS, X = (bytes([n]) * 28 for n in (0xD1, 0xD2, 0xD3, 0xD4))
RET = b"\xe0" + bytes([0xC1]) * 28
ANCH = ["https://example.invalid/proposal.json", bytes([0x0B]) * 32]
PRIOR = [bytes([0xAA]) * 32, 0]
DEP = 100_000_000_000
Q = Tag(30, [2, 3])


def e0(c):
    return b"\xe0" + c


def prop(action, account=RET, anchor=ANCH):
    return [DEP, account, action, anchor]


def props(*actions, tagged=False, indef=False):
    s = A([prop(a) for a in actions], indef=indef)
    return Tag(258, s) if tagged else s


def P(*actions, **kw):
    return [(20, props(*actions, **kw))]


V = []


def v(id_, cat, ledger, label, body):
    V.append((id_, cat, ledger, label, body))


# A: coverage the 17 vectors leave open (ledger-valid unless noted)
v("A01_treasury_2nd_of_3", "A", "valid", "USE_FOUND", P([2, M([(e0(O), 1), (e0(W), 2), (e0(X), 3)]), None]))
v("A02_treasury_script_hdr_f0", "A", "valid", "USE_FOUND", P([2, {b"\xf0" + W: 1}, None]))
v("A03_treasury_mainnet_e1", "A", "valid", "USE_FOUND", P([2, {b"\xe1" + W: 1}, None]))
v("A04_treasury_mainnet_f1", "A", "valid", "USE_FOUND", P([2, {b"\xf1" + W: 1}, None]))
v("A05_committee_removed_and_added", "A", "rule", "USE_FOUND", P([4, None, [[0, W]], M([([0, W], 500)]), Q]))
v("A06_removed_3rd_of_3_tagged", "A", "valid", "USE_FOUND", P([4, None, Tag(258, [[0, O], [1, X], [0, W]]), {}, Q]))
v("A07_removed_indef_untagged", "A", "valid", "USE_FOUND", P([4, None, A([[0, O], [0, W]], indef=True), {}, Q]))
v("A08_removed_tagged_indef", "A", "valid", "USE_FOUND", P([4, None, Tag(258, A([[0, W]], indef=True)), {}, Q]))
v("A09_added_indef_map_2nd", "A", "valid", "USE_FOUND", P([4, None, [], M([([0, O], 5), ([0, W], 6)], indef=True), Q]))
v("A10_added_script_cred", "A", "valid", "USE_FOUND", P([4, None, [], M([([1, W], 7)]), Q]))
v("A11_removed_script_cred", "A", "valid", "USE_FOUND", P([4, None, [[1, W]], {}, Q]))
v("A12_two_props_W_in_2nd", "A", "valid", "USE_FOUND", P([2, {e0(O): 1}, None], [2, {e0(W): 1}, None]))
v("A13_tagged_info_then_add", "A", "valid", "USE_FOUND", P([6], [4, None, [], M([([0, W], 9)]), Q], tagged=True))
v("A14_three_props_constitution_3rd", "A", "valid", "USE_FOUND", P([1, None, [10, 0]], [3, PRIOR], [5, None, [ANCH, W]]))
v("A15_param_policy_prior_costmodels", "A", "valid", "USE_FOUND", P([0, PRIOR, M([(18, M([(2, [1, 2, 3])])), (0, 44)]), W]))
v("A16_constitution_indef_anchor", "A", "valid", "USE_FOUND", P([5, None, [A(ANCH, indef=True), W]]))
v("A17_kind_nonminimal_u8", "A", "valid", "USE_FOUND", P([U(2, width=1), {e0(W): 1}, None]))
v("A18_hash_nonminimal_len", "A", "valid", "USE_FOUND", P([0, None, {0: 44}, B(W, width=2)]))
v("A19_proposals_indef", "A", "valid", "USE_FOUND", P([2, {e0(W): 1}, None], indef=True))
v("A20_key20_first_then_fee_ttl", "A", "valid", "USE_FOUND", P([4, None, [[0, W]], {}, Q]) + [(2, 170000), (3, 1000)])
v("A21_fee_key20_ttl", "A", "valid", "USE_FOUND", [(2, 1), (20, props([5, None, [ANCH, W]])), (3, 5)])
v("A22_removed_W_add_W_script", "A", "rule", "USE_FOUND", P([4, None, [[1, W]], M([([0, W], 1)]), Q]))
# B: controls -- the hash sits only in untyped data, or is absent
v("B01_prior_txid_prefix_W", "B", "valid", "NO_USE", P([3, [W + bytes(4), 0]]))
v("B02_anchor_hash_prefix_W", "B", "valid", "NO_USE", [(20, A([prop([6], anchor=["https://x.invalid/a", W + bytes(4)])]))])
v("B03_anchor_url_hex_W", "B", "valid", "NO_USE", [(20, A([prop([6], anchor=["https://x.invalid/" + W.hex(), bytes(32)])]))])
v("B04_committee_empty_tagged", "B", "valid", "NO_USE", P([4, None, Tag(258, []), {}, Q]))
v("B05_hard_fork_prior", "B", "valid", "NO_USE", P([1, PRIOR, [11, 0]]))
v("B06_two_props_controls", "B", "valid", "NO_USE", P([0, None, {0: 44}, O], [2, {e0(O): 5}, OS]))
v("B07_treasury_indef_unwatched", "B", "valid", "NO_USE", P([2, M([(e0(O), 1), (b"\xf0" + X, 2)], indef=True), OS]))
v("B08_committee_indef_unwatched", "B", "valid", "NO_USE", P([4, PRIOR, Tag(258, A([[0, O]], indef=True)), M([([1, X], 5)], indef=True), Q]))
v("B09_unit_interval_bare", "B", "invalid", "NO_USE", P([4, None, [], {}, [1, 2]]))
v("B10_W_as_epoch_bytes", "B", "invalid", "NO_USE", P([4, None, [], M([([0, O], W)]), Q]))
v("B11_W_as_coin_bytes", "B", "invalid", "NO_USE", P([2, {e0(O): W}, None]))
v("B12_W_in_param_update", "B", "invalid", "NO_USE", P([0, None, {99: W}, None]))
# C: INCOMPLETE triggers (watched hash absent)
v("C01_kind2_arity4", "C", "invalid", "INCOMPLETE", P([2, {e0(O): 1}, None, None]))
v("C02_kind6_arity2", "C", "invalid", "INCOMPLETE", P([6, None]))
v("C03_kind3_arity3", "C", "invalid", "INCOMPLETE", P([3, None, None]))
v("C04_kind_u64max", "C", "invalid", "INCOMPLETE", P([U(2**64 - 1), None]))
v("C05_kind_negative", "C", "invalid", "INCOMPLETE", P([Neg(-1), None]))
v("C06_kind_text", "C", "invalid", "INCOMPLETE", P([T("2"), {e0(O): 1}, None]))
v("C07_kind_bool", "C", "invalid", "INCOMPLETE", P([TRUE]))
v("C08_gov_action_empty", "C", "invalid", "INCOMPLETE", P(A([])))
v("C09_gov_action_int", "C", "invalid", "INCOMPLETE", P(6))
v("C10_gov_action_map", "C", "invalid", "INCOMPLETE", P(M([(0, 6)])))
v("C11_removal_tag24", "C", "invalid", "INCOMPLETE", P([4, None, Tag(24, [[0, O]]), {}, Q]))
v("C12_removal_tag55799", "C", "invalid", "INCOMPLETE", P([4, None, Tag(55799, [[0, O]]), {}, Q]))
v("C13_removal_double_258", "C", "invalid", "INCOMPLETE", P([4, None, Tag(258, Tag(258, [[0, O]])), {}, Q]))
v("C14_added_map_tag258", "C", "invalid", "INCOMPLETE", P([4, None, [], Tag(258, M([([0, O], 5)])), Q]))
v("C15_treasury_map_tag259", "C", "invalid", "INCOMPLETE", P([2, Tag(259, {e0(O): 1}), None]))
v("C16_cred_kind2", "C", "invalid", "INCOMPLETE", P([4, None, [[2, O]], {}, Q]))
v("C17_cred_hash27", "C", "invalid", "INCOMPLETE", P([4, None, [[0, O[:27]]], {}, Q]))
v("C18_cred_arity3", "C", "invalid", "INCOMPLETE", P([4, None, [[0, O, 0]], {}, Q]))
v("C19_cred_bare_bytes", "C", "invalid", "INCOMPLETE", P([4, None, [O], {}, Q]))
v("C20_policy_27", "C", "invalid", "INCOMPLETE", P([0, None, {0: 44}, O[:27]]))
v("C21_policy_29", "C", "invalid", "INCOMPLETE", P([2, {e0(O): 1}, O + b"\x00"]))
v("C22_constitution_hash32", "C", "invalid", "INCOMPLETE", P([5, None, [ANCH, O + bytes(4)]]))
v("C23_policy_undefined", "C", "invalid", "INCOMPLETE", P([0, None, {0: 44}, UNDEF]))
v("C24_policy_int", "C", "invalid", "INCOMPLETE", P([2, {}, 5]))
v("C25_constitution_arity3", "C", "invalid", "INCOMPLETE", P([5, None, [ANCH, None, None]]))
v("C26_constitution_map", "C", "invalid", "INCOMPLETE", P([5, None, M([(0, None)])]))
v("C27_treasury_key_int", "C", "invalid", "INCOMPLETE", P([2, {5: 1}, None]))
v("C28_treasury_map_as_array", "C", "invalid", "INCOMPLETE", P([2, [e0(O), 1], None]))
v("C29_cred_kind_text", "C", "invalid", "INCOMPLETE", P([4, None, [[T("0"), O]], {}, Q]))
v("C30_treasury_key_text", "C", "invalid", "INCOMPLETE", P([2, {T(e0(O).hex()): 1}, None]))
v("C31_removal_is_map", "C", "invalid", "INCOMPLETE", P([4, None, M([([0, O], 1)]), {}, Q]))
v("C32_added_is_array", "C", "invalid", "INCOMPLETE", P([4, None, [], [[0, O]], Q]))
# D: a use beside a gap -- the use must dominate wherever a reader reaches it
v("D01_removed_W_then_bad", "D", "invalid", "USE_FOUND", P([4, None, [[0, W], [9, O]], {}, Q]))
v("D02_removed_bad_then_W", "D", "invalid", "USE_FOUND", P([4, None, [[9, O], [0, W]], {}, Q]))
v("D03_treasury_intkey_then_W", "D", "invalid", "USE_FOUND", P([2, M([(5, 1), (e0(W), 1)]), None]))
v("D04_removed_W_added_malformed", "D", "invalid", "USE_FOUND", P([4, None, [[0, W]], [1, 2], Q]))
v("D05_treasury_W_policy_bad", "D", "invalid", "USE_FOUND", P([2, {e0(W): 1}, O[:27]]))
v("D06_W_then_unknown_kind", "D", "invalid", "USE_FOUND", P([2, {e0(W): 1}, None], [7]))
v("D07_W_inside_unknown_kind", "D", "invalid", "INCOMPLETE", P([7, W], [6]))
v("D08_bad_prop_then_W_prop", "D", "invalid", "USE_FOUND", P([4, None, [[9, O]], {}, Q], [2, {e0(W): 1}, None]))
v("D09_unknown_prop_then_W_prop", "D", "invalid", "USE_FOUND", P([7, None], [2, {e0(W): 1}, None]))
v("D10_arity_prop_then_W_prop", "D", "invalid", "USE_FOUND", P([2, {e0(O): 1}], [5, None, [ANCH, W]]))
v("D11_W_wrong_arity_same_action", "D", "invalid", "AMBIG:INCOMPLETE|USE_FOUND", P([2, {e0(W): 1}, None, None]))
# E: hostile encodings
v("E01_indef_action_W", "E", "valid", "USE_FOUND", P(A([2, {e0(W): 1}, None], indef=True)))
v("E02_indef_action_info", "E", "valid", "NO_USE", P(A([6], indef=True)))
v("E03_indef_constitution_W", "E", "valid", "USE_FOUND", P([5, None, A([ANCH, W], indef=True)]))
v("E04_indef_cred_W", "E", "valid", "USE_FOUND", P([4, None, [A([0, W], indef=True)], {}, Q]))
v("E05_indef_cred_O", "E", "valid", "NO_USE", P([4, None, [A([0, O], indef=True)], {}, Q]))
v("E06_indef_constitution_O", "E", "valid", "NO_USE", P([5, None, A([ANCH, None], indef=True)]))
v("E07_chunked_account_W", "E", "pv12", "USE_FOUND", P([2, {B(e0(W), chunks=[10, 19]): 1}, None]))
v("E08_chunked_policy_W", "E", "pv12", "USE_FOUND", P([0, None, {0: 44}, B(W, chunks=[14, 14])]))
v("E09_chunked_cred_W", "E", "pv12", "USE_FOUND", P([4, None, [[0, B(W, chunks=[1, 27])]], {}, Q]))
v("E10_chunked_policy_O", "E", "pv12", "NO_USE", P([2, {e0(O): 1}, B(O, chunks=[28])]))
v("E11_chunked_zero_len_chunks_W", "E", "pv12", "USE_FOUND", P([0, None, {0: 44}, B(W, chunks=[0, 28, 0])]))
v("E12_dup_treasury_W", "E", "invalid", "USE_FOUND", P([2, M([(e0(W), 1), (e0(W), 2)]), None]))
v("E13_dup_treasury_O", "E", "invalid", "NO_USE", P([2, M([(e0(O), 1), (e0(O), 2)]), None]))
v("E14_dup_removed_W", "E", "invalid", "USE_FOUND", P([4, None, [[0, W], [0, W]], {}, Q]))
v("E15_dup_add_mixed_encoding", "E", "invalid", "USE_FOUND", P([4, None, [], M([([0, W], 1), ([0, B(W, chunks=[28])], 2)]), Q]))
v("E16_reward_hdr_60_W", "E", "invalid", "USE_FOUND", P([2, {b"\x60" + W: 1}, None]))
v("E17_reward_28B_is_W", "E", "invalid", "AMBIG:NO_USE|INCOMPLETE", P([2, {W: 1}, None]))
v("E18_reward_30B_W_at_1", "E", "invalid", "USE_FOUND", P([2, {e0(W) + b"\x00": 1}, None]))
v("E19_reward_30B_W_at_2", "E", "invalid", "AMBIG:NO_USE|INCOMPLETE", P([2, {b"\xe0\x00" + W: 1}, None]))
v("E20_reward_57B_base", "E", "invalid", "AMBIG:NO_USE|INCOMPLETE", P([2, {b"\x00" + O + W: 1}, None]))
v("E21_reward_empty", "E", "invalid", "AMBIG:NO_USE|INCOMPLETE", P([2, {b"": 1}, None]))
v("E22_deposit_acct_28B_W", "E", "invalid", "AMBIG:NO_USE|INCOMPLETE", [(20, A([prop([6], account=W)]))])
v("E23_proposals_tag259_W", "E", "invalid", "AMBIG:INCOMPLETE|USE_FOUND", [(20, Tag(259, A([prop([2, {e0(W): 1}, None])])))])
v("E24_proposals_tag24_hides_W", "E", "invalid", "INCOMPLETE", [(20, Tag(24, enc(A([prop([2, {e0(W): 1}, None])]))))])
v("E25_proposals_tag258_on_bytes", "E", "invalid", "INCOMPLETE", [(20, Tag(258, e0(W)))])
v("E26_proposal_entry_int", "E", "invalid", "INCOMPLETE", [(20, A([5]))])
v("E27_proposal_one_element", "E", "invalid", "INCOMPLETE", [(20, A([[DEP]]))])
v("E28_proposal_5_elems_W_extra", "E", "invalid", "AMBIG:NO_USE|INCOMPLETE", [(20, A([[DEP, RET, [6], ANCH, [0, W]]]))])
v("E29_proposal_3_elems_W", "E", "invalid", "USE_FOUND", [(20, A([[DEP, RET, [2, {e0(W): 1}, None]]]))])
v("E30_deposit_acct_text", "E", "invalid", "INCOMPLETE", [(20, A([[DEP, e0(O).hex(), [6], ANCH]]))])
v("E31_self_describe_action", "E", "invalid", "INCOMPLETE", P(Tag(55799, [2, {e0(O): 1}, None])))
v("E32_self_describe_action_W", "E", "invalid", "AMBIG:INCOMPLETE|USE_FOUND", P(Tag(55799, [2, {e0(W): 1}, None])))
v("E33_kind_bignum_tag2", "E", "invalid", "INCOMPLETE", P([Tag(2, b"\x02"), {e0(O): 1}, None]))
v("E34_kind_float", "E", "invalid", "INCOMPLETE", P([Raw(b"\xf9\x40\x00"), {e0(O): 1}, None]))
v("E35_shareable_sharedref_W", "E", "invalid", "AMBIG:INCOMPLETE|USE_FOUND", P([4, None, [Tag(28, [0, W])], M([(Tag(29, 0), 5)]), Q]))
v("E36_policy_self_describe_O", "E", "invalid", "INCOMPLETE", P([0, None, {0: 44}, Tag(55799, O)]))
v("E37_nonminimal_array_hdr_W", "E", "valid", "USE_FOUND", P(A([2, {e0(W): 1}, None], width=1)))
v("E38_policy_simple_null_alias", "E", "invalid", "INCOMPLETE", P([0, None, {0: 44}, Raw(b"\xf8\x16")]))
v("E39_dup_body_key20_W_first", "E", "invalid", "AMBIG:USE_FOUND|INCOMPLETE", [(20, props([2, {e0(W): 1}, None])), (20, props([6]))])
v("E40_tag258_removal_on_map_W", "E", "invalid", "AMBIG:INCOMPLETE|USE_FOUND", P([4, None, Tag(258, M([([0, W], 1)])), {}, Q]))

if __name__ == "__main__":
    out = []
    for id_, cat, ledger, label, body in V:
        raw = tx(body)
        m = evaluate(raw, W)
        ms = evaluate(raw, W, strict_len=True, two_element_ok=False)
        out.append({"id": id_, "cat": cat, "ledger": ledger, "label": label, "tx": raw.hex(),
                    "target": W.hex(), "model": m.get("verdict"), "model_strict": ms.get("verdict"),
                    "model_notes": m.get("notes")})
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    with open(sys.argv[2], "w") as f:
        for r in out:
            f.write(f"{r['id']}\t{r['tx']}\t{r['target']}\n")
    print(len(out), "vectors")
