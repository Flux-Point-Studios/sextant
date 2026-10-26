"""Mutation run against src/watchkey.rs in the scratch clone only."""
import subprocess, sys, os, json, time
REPO = "/tmp/claude-1000/-home-deci/93582ed9-742f-45d3-9e79-74b6bf1ef9fa/scratchpad/sextant-rt"
SRC = os.path.join(REPO, "src/watchkey.rs")
ENV = dict(os.environ, CARGO_TARGET_DIR="/tmp/claude-1000/-home-deci/93582ed9-742f-45d3-9e79-74b6bf1ef9fa/scratchpad/target-mut")
CMD = ["nice", "-n", "19", "cargo", "test", "-j", "4", "--no-fail-fast",
       "--test", "watchkey_golden", "--test", "watchkey_scripts", "--test", "watchkey_coverage",
       "--test", "watchkey_inputs", "--lib"]
EXTRA = ["--test", "rt_attacks"]  # second pass: does the red-team suite kill it?

ORIG = subprocess.run(["git", "-C", REPO, "show", "HEAD:src/watchkey.rs"], capture_output=True, text=True, check=True).stdout

M = [
 ("M01", "budget exhaustion keeps complete=true",
  "        if *budget == 0 {\n            scan.complete = false;\n            d.skip()", "        if *budget == 0 {\n            d.skip()"),
 ("M02", "drop native ref-script trailing-bytes check",
  "    if script.position() == script.input().len() {\n        Ok(())\n    } else {\n        Err(())\n    }", "    Ok(())"),
 ("M03", "accept indefinite bytes inside tag 24",
  "    let mut script = Decoder::new(d.bytes().map_err(|_| ())?);",
  "    let mut joined = Vec::new();\n    for chunk in d.bytes_iter().map_err(|_| ())? {\n        joined.extend_from_slice(chunk.map_err(|_| ())?);\n    }\n    let mut script = Decoder::new(&joined);"),
 ("M04", "per-output budget instead of shared",
  "    scan: &mut Scan,\n) -> Result<(), ()> {\n    let start = d.position();",
  "    scan: &mut Scan,\n) -> Result<(), ()> {\n    let mut local = WALK_BUDGET;\n    let _ = budget;\n    let budget = &mut local;\n    let start = d.position();"),
 ("M05", "drop tag-24 check", "    if d.tag().map_err(|_| ())?.as_u64() != 24 {\n        return Err(());\n    }", "    d.tag().map_err(|_| ())?;"),
 ("M06", "unknown script type accepted", "        1..=3 => return Ok(()),\n        _ => return Err(()),", "        _ => return Ok(()),"),
 ("M07", "drop [type, script] arity check", "    if script.array().map_err(|_| ())? != Some(2) {\n        return Err(());\n    }", "    script.array().map_err(|_| ())?;"),
 ("M08", "never inspect key 3", "        if key == 3\n", "        if key == 99\n"),
 ("M09", "ref-script error does not mark incomplete",
  "            .is_err()\n        {\n            scan.complete = false;\n        }", "            .is_err()\n        {\n        }"),
 ("M10", "misplaced break skipped instead of Err", "            Type::Break => return Err(()),", "            Type::Break => d.skip().map_err(|_| ())?,"),
 ("M11", "indefinite map accepts break while a value is owed",
  "                    if !top.owes_value && d.datatype().map_err(|_| ())? == Type::Break {", "                    if d.datatype().map_err(|_| ())? == Type::Break {"),
 ("M12", "indefinite bytes not joined (skipped)", "            Type::Bytes | Type::BytesIndef => {", "            Type::Bytes => {"),
 ("M13", "29-byte reward credential not matched", "                    29 => reward_credential(&leaf).is_some_and(|c| watched.contains(&c)),", "                    29 => false,"),
 ("M14", "budget never decremented", "        *budget -= 1;\n", ""),
 ("M15", "definite map counts pairs not items", "Some(pairs) => Some(pairs.checked_mul(2).ok_or(())?),", "Some(pairs) => Some(pairs),"),
 ("M16", "drop KNOWN_BODY_KEYS check", "            scan.complete &= KNOWN_BODY_KEYS.contains(&key);\n", ""),
 ("M17", "KNOWN_BODY_KEYS widened to 0..=22", "            scan.complete &= KNOWN_BODY_KEYS.contains(&key);", "            scan.complete &= key <= 22;"),
 ("M18", "drop native_script_use from transaction_use", "        native_script_use(witnesses, watched),\n    ];", "    ];"),
 ("M19", "drop witness_use from transaction_use", "        witness_use(witnesses, watched),\n", ""),
 ("M20", "drop output_use from transaction_use", "        output_use(body, watched),\n", ""),
 ("M21", "verdict: gap outranks use",
  "        if self.surfaces.found || self.inputs.found {\n            Verdict::UseFound\n        } else if self.surfaces.complete && self.inputs.complete {\n            Verdict::NoUse\n        } else {\n            Verdict::Incomplete\n        }",
  "        if !(self.surfaces.complete && self.inputs.complete) {\n            Verdict::Incomplete\n        } else if self.surfaces.found || self.inputs.found {\n            Verdict::UseFound\n        } else {\n            Verdict::NoUse\n        }"),
 ("M22", "surfaces complete = any instead of all", "            complete: scans.iter().all(|scan| scan.complete),", "            complete: scans.iter().any(|scan| scan.complete),"),
 ("M23", "input_use ignores is_valid", "    let consumed = if is_valid { 0 } else { 13 };", "    let _ = is_valid;\n    let consumed = 0;"),
 ("M24", "witness_use drops bootstrap", "        if key == 0 || key == 2 {", "        if key == 0 {"),
 ("M25", "output_use skips collateral return", "        16 => output_watched(d, watched, &mut budget, scan),", "        16 => d.skip().map_err(|_| ()),"),
 ("M26", "native ref script not walked", "        0 => collect_watched(&mut script, watched, budget, scan)?,", "        0 => {\n            script.skip().map_err(|_| ())?;\n        }"),
 ("M27", "certificate arity check dropped", "                        if cert_len != Some(arity) {\n                            scan.complete = false;\n                        }", ""),
 ("M28", "transaction_use passes is_valid=true", "        inputs: input_use(body, is_valid, watched, resolve),", "        inputs: input_use(body, true, watched, resolve),"),
 ("M29", "exhaustion stops the walk early (Ok) but marks gap",
  "        if *budget == 0 {\n            scan.complete = false;\n            d.skip().map_err(|_| ())?;\n            continue;\n        }",
  "        if *budget == 0 {\n            scan.complete = false;\n            return Ok(());\n        }"),
 ("M30", "budget limit 100_000 -> 1_000", "const WALK_BUDGET: u32 = 100_000;", "const WALK_BUDGET: u32 = 1_000;"),
 ("M31", "map output: legacy outputs refused", "    if output.datatype().map_err(|_| ())? != Type::Map {\n        return Ok(());\n    }", "    if output.datatype().map_err(|_| ())? != Type::Map {\n        return Err(());\n    }"),
 ("M32", "required signer of wrong length accepted", "                    Err(_) => return Err(()),\n                }\n                j += 1;\n            }\n        } else if d.skip().is_err() {\n            return Err(());\n        }\n        Ok(())\n    })\n}\n\n/// Whether a raw address", "                    Err(_) => {}\n                }\n                j += 1;\n            }\n        } else if d.skip().is_err() {\n            return Err(());\n        }\n        Ok(())\n    })\n}\n\n/// Whether a raw address"),
]

def run(args, timeout=900):
    t = time.time()
    p = subprocess.run(CMD + args if args is not None else CMD, cwd=REPO, env=ENV, capture_output=True, text=True, timeout=timeout)
    out = p.stdout + p.stderr
    if "could not compile" in out or "error[E" in out:
        return "COMPILE_ERROR", out, time.time() - t
    return ("SURVIVED" if p.returncode == 0 else "KILLED"), out, time.time() - t

def failing(out):
    return sorted({l.split()[1] for l in out.splitlines() if l.startswith("test ") and l.rstrip().endswith("FAILED")})

results = []
sel = sys.argv[1:] 
try:
    open(SRC, "w").write(ORIG)
    status, out, dt = run([])
    print(f"CONTROL (unmutated) -> {status} in {dt:.0f}s", flush=True)
    if status != "SURVIVED":
        print(out[-3000:]); sys.exit(2)
    for mid, desc, old, new in M:
        if sel and mid not in sel: continue
        n = ORIG.count(old)
        if n != 1:
            print(f"{mid} BAD-PATTERN count={n}", flush=True); results.append((mid, desc, "BAD-PATTERN", [], None)); continue
        open(SRC, "w").write(ORIG.replace(old, new))
        status, out, dt = run([])
        kills = failing(out)
        rt = None
        if status == "SURVIVED":
            s2, o2, _ = run(EXTRA)
            rt = (s2, failing(o2))
        print(f"{mid} {status:13s} {dt:4.0f}s  {desc}  kills={kills[:6]}{' ...' if len(kills)>6 else ''}  redteam={rt}", flush=True)
        results.append((mid, desc, status, kills, rt))
finally:
    open(SRC, "w").write(ORIG)
json.dump(results, open("/tmp/claude-1000/-home-deci/93582ed9-742f-45d3-9e79-74b6bf1ef9fa/scratchpad/logs/mutation_results.json", "w"), indent=1)
