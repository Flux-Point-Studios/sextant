//! The U1 F5 vectors: Byron addresses whose root is the watched VKH. The ledger types
//! a Byron address's root as its payment key hash, and the VKH's own vkey witness
//! spends a root equal to it, so the root is the address's payment credential in an
//! output, a collateral return or a consumed input. An output or consumed input whose
//! address yields no payment credential leaves the scan open. The oracle is
//! r57-live's `scripts/u1_f5_vectors.json`, written by gen_u1_f5_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_f5_vectors.json");

oracle_tests!(
    ORACLE,
    "5c7032fdb58e61d069e31155eee0dd2300c8aa63fc73b3a058e556c1cc22dc10";
    f5_pay_to_byron_root_vkh,
    f5_spend_byron_root_vkh_vkey_witness,
    f5_spend_byron_root_vkh_bootstrap_witness_ledger_invalid,
    f5_spend_byron_root_vkh_other_witness_ledger_invalid,
    f5_pay_to_byron_root_vkh_mainnet,
    f5_pay_to_byron_root_vkh_redeem_type2,
    g_icarus_built_out,
    g_magic1_outmap,
    g_daedalus_testnet_colret,
    g_redeem_type2_magic_in,
    g_magic1_in_collateral_invalid,
    o_tag24_nonminimal2_out,
    o_crc_nonminimal8_outmap,
    a_key_nonmin8_colret,
    e_root_len_w8_out,
    e_attrs_100_unknown_in,
    e_type2_magic_out,
    g_fixture_mainnet_192261940_4_out,
    g_fixture_mainnet_192261940_4_in,
    g_mainnet_daedalus_outmap,
    o_attrs_indef_magic_out,
    o_type1_in,
    o_outer_nonminimal_out,
    o_root27_out,
    byron_root_vkh_crc_broken_out,
    byron_root_vkh_crc_broken_in,
    byron_root_vkh_type3_out,
);
