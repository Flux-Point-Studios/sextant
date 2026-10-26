//! The 21 golden U1 watched-key vectors, v2. The oracle is r57-live's
//! `scripts/u1_watched_key_vectors_v2.json`, written by gen_u1_vectors_v2.py: the
//! archived v1 (SHA-256 3b4bc95e) with each reviewed semantic correction recorded
//! on its vector.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_watched_key_vectors_v2.json");

oracle_tests!(
    ORACLE,
    "0041b40773dde90e4912f12f049ffef61e25f8e14fff8d519c53dae714dc5df6";
    supported_era_no_use,
    output_payment,
    output_stake,
    required_signer_array,
    required_signer_tagged_set,
    vkey_witness_c_control,
    withdrawal,
    pool_owner_tagged_set,
    pool_reward_account,
    native_script_sig,
    native_script_deep70,
    reference_script_native,
    collateral_return_refscript,
    proposal_reward_array,
    proposal_reward_tagged_set,
    spent_input_payment,
    phase2_collateral_input,
    unsupported_era_body_key,
    unknown_cert_kind,
    undecodable,
    unresolved_spent_input,
);
