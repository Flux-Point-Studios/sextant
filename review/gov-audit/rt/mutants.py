"""Rust mutants for gov_action_watched / proposal_use (exact single-occurrence edits)."""
TREAS = """                while seq_has_next(d, entries, i).map_err(|_| ())? {
                    scan.found |= reward_account_watched(d, watched)?;
                    d.skip().map_err(|_| ())?;
                    i += 1;
                }"""
REMOVAL_ARM = """            (true, 4, 2) => {
                let members = input_set_len(d).map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, members, i).map_err(|_| ())? {
                    scan.found |= cold_credential_watched(d, watched)?;
                    i += 1;
                }
            }
"""
ADD_ARM = """            (true, 4, 3) => {
                let entries = d.map().map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, entries, i).map_err(|_| ())? {
                    scan.found |= cold_credential_watched(d, watched)?;
                    d.skip().map_err(|_| ())?;
                    i += 1;
                }
            }
"""
TREAS_ARM = """            (true, 2, 1) => {
                let entries = d.map().map_err(|_| ())?;
                let mut i = 0u64;
                while seq_has_next(d, entries, i).map_err(|_| ())? {
                    scan.found |= reward_account_watched(d, watched)?;
                    d.skip().map_err(|_| ())?;
                    i += 1;
                }
            }
"""
MUTANTS = [
    ("M01_drop_removal_set_walk", REMOVAL_ARM, ""),
    ("M02_drop_add_map_walk", ADD_ARM, ""),
    ("M03_drop_kind5_policy",
     "                d.skip().map_err(|_| ())?;\n                scan.found |= script_hash_watched(d, watched)?;\n",
     "                d.skip().map_err(|_| ())?;\n                d.skip().map_err(|_| ())?;\n"),
    ("M04_unknown_kind_complete", "    if !typed {\n        scan.complete = false;\n    }\n", ""),
    ("M05_no_header_strip_treasury", TREAS,
     TREAS.replace("scan.found |= reward_account_watched(d, watched)?;",
                   "scan.found |= { let a = read_bytes(d).map_err(|_| ())?; a.len() >= 28 && watched.contains(&<[u8; 28]>::try_from(&a[0..28]).unwrap()) };")),
    ("M06_drop_treasury_recipients", TREAS_ARM, ""),
    ("M07_drop_kind0_policy", "(true, 0, 3) | (true, 2, 2) =>", "(true, 2, 2) =>"),
    ("M08_drop_kind2_policy", "(true, 0, 3) | (true, 2, 2) =>", "(true, 0, 3) =>"),
    ("M09_arity_kind4_6", "        4 => Some(5),", "        4 => Some(6),"),
    ("M10_indefinite_typed_unchecked", "is_some_and(|arity| len == Some(arity))", "is_some_and(|arity| len.map_or(true, |l| l == arity))"),
    ("M11_empty_action_complete", "    if !seq_has_next(d, len, 0).map_err(|_| ())? {\n        scan.complete = false;\n        return Ok(());",
     "    if !seq_has_next(d, len, 0).map_err(|_| ())? {\n        return Ok(());"),
    ("M12_removal_any_tag", "                let members = input_set_len(d).map_err(|_| ())?;",
     "                if d.datatype().map_err(|_| ())? == Type::Tag { d.tag().map_err(|_| ())?; }\n                let members = d.array().map_err(|_| ())?;"),
    ("M13_cred_kind2_accepted", "d.u64().map_err(|_| ())? > 1 {", "d.u64().map_err(|_| ())? > 2 {"),
    ("M14_cred_arity_unchecked", "if d.array().map_err(|_| ())? != Some(2) || d.u64()", "if { d.array().map_err(|_| ())?; false } || d.u64()"),
    ("M15_hash_wrong_len_ok", "    let hash: [u8; 28] = bytes.as_slice().try_into().map_err(|_| ())?;\n    Ok(watched.contains(&hash))",
     "    Ok(<[u8; 28]>::try_from(bytes.as_slice()).is_ok_and(|h| watched.contains(&h)))"),
    ("M16_constitution_arity_unchecked", "                if d.array().map_err(|_| ())? != Some(2) {\n                    return Err(());\n                }\n",
     "                d.array().map_err(|_| ())?;\n"),
    ("M17_treasury_nonbytes_key_swallowed", TREAS,
     TREAS.replace("scan.found |= reward_account_watched(d, watched)?;",
                   "match reward_account_watched(d, watched) { Ok(f) => scan.found |= f, Err(()) => d.skip().map_err(|_| ())? }")),
    ("M18_proposal_ignores_gov_errors", "                        gov_action_watched(d, watched, scan)?;", "                        let _ = gov_action_watched(d, watched, scan);"),
    ("M20_typed_ignores_len", "gov_action_arity(kind).is_some_and(|arity| len == Some(arity))", "gov_action_arity(kind).is_some()"),
    ("M21_treasury_value_not_skipped", TREAS, TREAS.replace("                    d.skip().map_err(|_| ())?;\n", "")),
    ("M22_removal_first_only", "                while seq_has_next(d, members, i).map_err(|_| ())? {\n                    scan.found |= cold_credential_watched(d, watched)?;",
     "                while seq_has_next(d, members, i).map_err(|_| ())? {\n                    let f = cold_credential_watched(d, watched)?; if i == 0 { scan.found |= f; }"),
    ("M23_add_map_first_only", "                while seq_has_next(d, entries, i).map_err(|_| ())? {\n                    scan.found |= cold_credential_watched(d, watched)?;",
     "                while seq_has_next(d, entries, i).map_err(|_| ())? {\n                    let f = cold_credential_watched(d, watched)?; if i == 0 { scan.found |= f; }"),
    ("M24_treasury_first_only", TREAS,
     TREAS.replace("scan.found |= reward_account_watched(d, watched)?;", "let f = reward_account_watched(d, watched)?; if i == 0 { scan.found |= f; }")),
    ("M25_proposals_first_only", "                    } else if k == 2 {\n", "                    } else if k == 2 && j == 0 {\n"),
    ("M26_treasury_header_e0_only", TREAS,
     TREAS.replace("scan.found |= reward_account_watched(d, watched)?;",
                   "scan.found |= { let a = read_bytes(d).map_err(|_| ())?; a.first() == Some(&0xe0) && reward_credential(&a).is_some_and(|c| watched.contains(&c)) };")),
    ("M28_arity_kind6_2", "        6 => Some(1),", "        6 => Some(2),"),
    ("M29_arity_kind1_4", "        1 | 2 | 5 => Some(3),", "        1 => Some(4),\n        2 | 5 => Some(3),"),
    ("M30_arity_kind3_3", "        3 => Some(2),", "        3 => Some(3),"),
    ("M31_policy_null_rejected", "    if d.datatype().map_err(|_| ())? == Type::Null {\n        d.skip().map_err(|_| ())?;\n        return Ok(false);\n    }\n    hash28_watched(d, watched)",
     "    hash28_watched(d, watched)"),
    ("M32_cred_kind_unchecked", "|| d.u64().map_err(|_| ())? > 1 {", "|| { d.skip().map_err(|_| ())?; false } {"),
    ("M33_kind5_reads_anchor_slot", "                d.skip().map_err(|_| ())?;\n                scan.found |= script_hash_watched(d, watched)?;\n",
     "                scan.found |= script_hash_watched(d, watched).unwrap_or(false);\n                d.skip().map_err(|_| ())?;\n"),
]
