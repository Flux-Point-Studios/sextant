//! The U1 Byron vectors: spent inputs resolved to Byron and other credential-free
//! addresses, and the witness rows that can carry the watched key. A well-formed
//! Byron address closes its input, since the key behind it spends only through a
//! bootstrap witness; any other credential-free address leaves the input open, and
//! a witness row is read only in its CDDL shape. The oracle is r57-live's
//! `scripts/u1_byron_vectors.json`, written by gen_u1_byron_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_byron_vectors.json");

oracle_tests!(
    ORACLE,
    "4da9be0637bfee61a21267f2022a982f7da40a2c4b92a22cd2cb2ce4f07ec102";
    byron_icarus_unwatched,
    byron_daedalus_unwatched,
    byron_watched_bootstrap,
    byron_watched_vkey_witness,
    byron_tagged_set_control,
    byron_indefinite_row,
    byron_and_shelley_watched,
    byron_crc_mismatch,
    byron_trailing_byte,
    byron_truncated,
    byron_header_only,
    byron_outer_arity_1,
    byron_payload_arity_2,
    byron_root_27_bytes,
    byron_attributes_not_a_map,
    byron_payload_trailing_byte,
    byron_foreign_tag,
    byron_chunked_payload,
    byron_indefinite_outer,
    unsupported_reward_account,
    unsupported_header_nibble_9,
    unsupported_empty,
    unsupported_short_shelley,
    witness_bootstrap_vkey_31,
    witness_bootstrap_vkey_not_bytes,
    witness_bootstrap_arity_3,
    witness_bootstrap_arity_2,
    witness_vkey_arity_4,
    witness_bootstrap_row_not_array,
    witness_bootstrap_slot_map,
    dominance_malformed_row_then_watched,
    dominance_number_row_then_watched,
    dominance_bad_byron_watched_vkey,
    dominance_reward_input_then_watched_input,
);
