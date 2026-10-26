//! The U1 boundary vectors: a reference input's signature counts through the
//! witness set, and data the ledger only carries -- an inline datum, Plutus data,
//! a redeemer, and auxiliary data with its metadata and scripts -- is a mention.
//! The oracle is r57-live's `scripts/u1_boundary_vectors.json`, written by
//! gen_u1_boundary_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_boundary_vectors.json");

oracle_tests!(
    ORACLE,
    "e6ba3c4e847f604190b74faf3687ff8af3cfddefdf174827bd9150064354cedf";
    reference_input_signed,
    reference_input_unsigned,
    inline_datum_mention,
    plutus_data_mention,
    redeemer_mention,
    aux_script_allegra_mention,
    aux_script_alonzo_mention,
    aux_metadata_mention,
);
