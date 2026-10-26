//! The 21 golden U1 watched-key vectors. The oracle is r57-live's
//! `scripts/u1_watched_key_vectors.json`, git blob a32cf41a; its CRLF Windows
//! working copy hashes to d0c1ea33.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_watched_key_vectors.json");

oracle_tests!(
    ORACLE,
    "3b4bc95ec13a600a5dde8c552c4600bf5d67634894a9abde709929e9ee5eee39";
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
