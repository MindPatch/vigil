pub mod strings;
pub mod constants;
pub mod eval_unwrap;
pub mod control_flow;

pub struct DeobfuscateResult {
    pub source: String,
    pub transforms_applied: Vec<TransformRecord>,
}

pub struct TransformRecord {
    pub pass_name: &'static str,
    pub changes: usize,
}

pub fn deobfuscate(source: &str) -> DeobfuscateResult {
    let mut current = source.to_string();
    let mut records = Vec::new();

    let passes: Vec<(&str, fn(&str) -> (String, usize))> = vec![
        ("string_decode", strings::decode_all),
        ("constant_fold", constants::fold),
        ("eval_unwrap", eval_unwrap::unwrap),
        ("control_flow", control_flow::simplify),
    ];

    // Run passes iteratively until no more changes (max 5 iterations to prevent loops)
    for iteration in 0..5 {
        let mut total_changes = 0;

        for (name, pass_fn) in &passes {
            let (output, changes) = pass_fn(&current);
            if changes > 0 {
                current = output;
                records.push(TransformRecord {
                    pass_name: name,
                    changes,
                });
                total_changes += changes;
            }
        }

        if total_changes == 0 {
            break;
        }

        if iteration == 4 {
            records.push(TransformRecord {
                pass_name: "iteration_limit",
                changes: 0,
            });
        }
    }

    DeobfuscateResult {
        source: current,
        transforms_applied: records,
    }
}
