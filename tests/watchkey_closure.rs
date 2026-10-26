//! The U1 closure vectors: every shape the scan reads is closed, so an unknown
//! witness-set or output-map key, a malformed reference script or a proposal of
//! the wrong arity reads INCOMPLETE inside an otherwise complete transaction. The
//! oracle is r57-live's `scripts/u1_closure_vectors.json`, written by
//! gen_u1_closure_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_closure_vectors.json");

oracle_tests!(
    ORACLE,
    "0b7e8588ffd9618af4f28a3c0c9776bd668422e7c0b83629ea01de986e355ba5";
    witness_unknown_key,
    witness_known_keys,
    output_unknown_key,
    output_known_keys,
    plutus_refscript_missing_bytecode,
    plutus_refscript_wrong_type,
    plutus_refscript_trailing_bytes,
    native_refscript_trailing_bytes,
    plutus_refscript_valid,
    refscript_without_tag24,
    refscript_foreign_tag,
    proposal_two_elements,
    proposal_three_elements,
    proposal_five_elements,
    proposal_four_elements,
);
