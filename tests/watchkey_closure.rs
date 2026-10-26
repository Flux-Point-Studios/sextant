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
    "57d4a1199282097acc9bf35f3516335c9859e1ba6dd895bc31c3b23fa6db1298";
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
    refscript_arity_three,
    proposal_two_elements,
    proposal_three_elements,
    proposal_five_elements,
    proposal_four_elements,
    body_key_10,
    body_key_12,
    certificate_wrong_arity,
    blob_after_empty_map,
);
