//! The U1 governance vectors: the typed credential positions of a Conway
//! gov_action, treasury recipients, committee members removed and added, and the
//! guardrail or constitution script hash. The oracle is r57-live's
//! `scripts/u1_governance_vectors.json`, written by gen_u1_governance_vectors.py.

#[macro_use]
mod common;

const ORACLE: &str = include_str!("vectors/u1_governance_vectors.json");

oracle_tests!(
    ORACLE,
    "98639ca625ff1baad1606e302f4678c091ef61448f741267a8283b13a1a24cea";
    gov_treasury_recipient,
    gov_treasury_policy,
    gov_committee_added,
    gov_committee_removed,
    gov_committee_removed_tagged_sets,
    gov_parameter_change_policy,
    gov_constitution_script,
    gov_control_parameter_change,
    gov_control_hard_fork,
    gov_control_treasury,
    gov_control_no_confidence,
    gov_control_update_committee,
    gov_control_new_constitution,
    gov_control_info,
    gov_unknown_action_kind,
    gov_wrong_arity,
    gov_unexpected_set_tag,
);
