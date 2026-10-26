//! The U1 shape vectors: shapes the scan must read, and framings it must refuse. A
//! certificate is read by its arity in either length form, as is a voter, `[kind 0-4,
//! 28-byte hash]`. Nesting has no limit short of the transaction size, deep auxiliary and
//! Plutus data are mentions, a break a repeated key would hide leaves the transaction
//! open, and only an exactly framed envelope is a transaction. The oracle is r57-live's
//! `scripts/u1_shape_vectors.json`, written by gen_u1_shape_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_shape_vectors.json");

oracle_tests!(
    ORACLE,
    "54d67bc7ac099dc82482e47d0f95c76732ea15c6a3397cbabb4173d0957ffb47";
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
    voter_definite_control,
    voter_indefinite_control,
    voter_definite_watched,
    voter_indefinite_watched,
    voter_definite_three,
    voter_indefinite_three,
    voter_indefinite_kind_only,
    voter_definite_kind_only,
    voter_not_an_array_then_watched,
    voter_unknown_kind,
    voter_bool_kind,
    voter_hash_short,
    voter_hash_not_bytes_then_watched,
    voter_three_watched,
    voter_three_then_watched,
    deep_aux_398,
    deep_aux_deepest,
    deep_aux_beside_a_watched_vkey,
    deep_native_script_watched,
    deep_native_script_in_an_indefinite_witness_map,
    deep_output_value,
    deep_plutus_datum,
    break_hidden_by_a_repeated_key,
    framing_four_items,
    framing_aux_missing,
    framing_aux_cut_short,
    framing_aux_break,
    framing_trailing_byte,
    framing_indefinite_outer,
    framing_three_items,
    framing_three_items_spending_the_watched_key,
    framing_three_items_deep_aux,
    framing_two_items,
    framing_two_items_then_flag_and_aux,
    framing_flag_not_a_bool,
    framing_flag_self_described,
    framing_body_self_described,
    framing_witness_set_self_described,
    framing_witness_set_null,
    framing_five_items,
    framing_five_declared_four_present,
    aux_text_utf8_control,
    aux_text_invalid_utf8,
    aux_text_chunk_splits_a_character,
);
