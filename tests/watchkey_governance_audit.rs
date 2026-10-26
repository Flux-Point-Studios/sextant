//! The independent governance auditor's vectors: multiple proposals, recipients and
//! committee members, the watched key in a later position, non-0xE0 reward
//! headers, and malformed shapes that must refuse. The oracle is r57-live's
//! `scripts/u1_governance_audit_vectors.json`, imported with the auditor's ids
//! and verdicts unchanged by gen_u1_governance_audit_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_governance_audit_vectors.json");

oracle_tests!(
    ORACLE,
    "df12c450aa98ace762f3c94dbe947343e57a070d76ae10409c5a5021ccedfdc6";
    a01_treasury_2nd_of_3,
    a02_treasury_script_hdr_f0,
    a03_treasury_mainnet_e1,
    a04_treasury_mainnet_f1,
    a05_committee_removed_and_added,
    a06_removed_3rd_of_3_tagged,
    a09_added_indef_map_2nd,
    a10_added_script_cred,
    a11_removed_script_cred,
    a12_two_props_w_in_2nd,
    a13_tagged_info_then_add,
    a14_three_props_constitution_3rd,
    c08_gov_action_empty,
    c16_cred_kind2,
    c17_cred_hash27,
    c20_policy_27,
    c21_policy_29,
    c22_constitution_hash32,
    c25_constitution_arity3,
    c27_treasury_key_int,
);
