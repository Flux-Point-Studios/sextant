//! The U1 shape vectors: ledger-valid shapes the scan must read. A certificate is read by
//! its arity in either length form, nesting has no limit short of the transaction size,
//! deep auxiliary and Plutus data are mentions, and a break a repeated key would hide
//! leaves the transaction open. The oracle is r57-live's `scripts/u1_shape_vectors.json`,
//! written by gen_u1_shape_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_shape_vectors.json");

oracle_tests!(
    ORACLE,
    "552fb830429b240ef39e059a1b7cba13c8fdec3d7cf6944140b8384b9c584fdc";
    cert_indefinite_vote_deleg,
    cert_indefinite_vote_deleg_watched,
    cert_definite_vote_deleg,
    cert_indefinite_stake_registration,
    cert_definite_stake_registration,
    cert_indefinite_stake_delegation,
    cert_definite_stake_delegation,
    cert_indefinite_reg_cert,
    cert_definite_reg_cert,
    cert_indefinite_one_short,
    cert_indefinite_one_long,
    cert_indefinite_kind_only,
    cert_definite_break_for_an_element,
    cert_short_then_watched,
    deep_aux_398,
    deep_aux_deepest,
    deep_aux_beside_a_watched_vkey,
    deep_native_script_watched,
    deep_native_script_in_an_indefinite_witness_map,
    deep_output_value,
    deep_plutus_datum,
    break_hidden_by_a_repeated_key,
);
