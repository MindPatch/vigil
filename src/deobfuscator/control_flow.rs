use regex::Regex;
use std::sync::LazyLock;

static DEAD_IF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"if\s*\(\s*(?:false|0|!1)\s*\)\s*\{").unwrap());
static TRUE_IF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"if\s*\(\s*(?:true|1|!0)\s*\)\s*\{").unwrap());
static LOGICAL_OR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:""|''|false|null)\s*\|\|\s*([^,;\n]+)"#).unwrap());
static COMMA_EXPR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\s*(?:0|void\s+0|undefined|null)\s*,\s*(\w+(?:\.\w+)*)\s*\)").unwrap()
});

pub fn simplify(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let (s, n) = remove_dead_if_false(&result);
    result = s;
    total += n;

    let (s, n) = simplify_if_true(&result);
    result = s;
    total += n;

    let (s, n) = simplify_ternary_const(&result);
    result = s;
    total += n;

    let (s, n) = simplify_logical_or_const(&result);
    result = s;
    total += n;

    let (s, n) = simplify_comma_expression(&result);
    result = s;
    total += n;

    (result, total)
}

fn find_brace_block(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let len = bytes.len();
    if start >= len || bytes[start] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    let mut i = start;

    while i < len {
        let b = bytes[i];

        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < len {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if b == b'"' || b == b'\'' {
            let quote = b;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if b == b'`' {
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'`' {
                    i += 1;
                    break;
                }
                if bytes[i] == b'$' && i + 1 < len && bytes[i + 1] == b'{' {
                    i += 2;
                    let mut interp_depth = 1i32;
                    while i < len && interp_depth > 0 {
                        if bytes[i] == b'{' {
                            interp_depth += 1;
                        } else if bytes[i] == b'}' {
                            interp_depth -= 1;
                        } else if bytes[i] == b'"' || bytes[i] == b'\'' {
                            let q = bytes[i];
                            i += 1;
                            while i < len {
                                if bytes[i] == b'\\' {
                                    i += 2;
                                    continue;
                                }
                                if bytes[i] == q {
                                    break;
                                }
                                i += 1;
                            }
                        }
                        i += 1;
                    }
                    continue;
                }
                i += 1;
            }
            continue;
        }

        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

fn remove_dead_if_false(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut changes = 0;

    loop {
        let m = match DEAD_IF_RE.find(&result) {
            Some(m) => m,
            None => break,
        };
        let brace_start = m.end() - 1;
        let block_end = match find_brace_block(&result, brace_start) {
            Some(e) => e,
            None => break,
        };

        let after = result[block_end..].trim_start();
        if after.starts_with("else") {
            let ws_after_block = result[block_end..].len() - after.len();
            let else_abs = block_end + ws_after_block;
            let past_else = &result[else_abs + 4..];
            let ws_after_else = past_else.len() - past_else.trim_start().len();
            let else_brace_start = else_abs + 4 + ws_after_else;
            if else_brace_start < result.len() && result.as_bytes()[else_brace_start] == b'{' {
                if let Some(else_end) = find_brace_block(&result, else_brace_start) {
                    let else_body = &result[else_brace_start + 1..else_end - 1];
                    result = format!(
                        "{}{}{}",
                        &result[..m.start()],
                        else_body.trim(),
                        &result[else_end..]
                    );
                    changes += 1;
                    continue;
                }
            }
        }

        result = format!("{}{}", &result[..m.start()], &result[block_end..]);
        changes += 1;
    }

    (result, changes)
}

fn simplify_if_true(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut changes = 0;

    loop {
        let m = match TRUE_IF_RE.find(&result) {
            Some(m) => m,
            None => break,
        };
        let brace_start = m.end() - 1;
        let block_end = match find_brace_block(&result, brace_start) {
            Some(e) => e,
            None => break,
        };

        let body = result[brace_start + 1..block_end - 1].trim().to_string();

        let after = result[block_end..].trim_start();
        let skip_end = if after.starts_with("else") {
            let ws_len = result[block_end..].len() - after.len();
            let else_abs = block_end + ws_len;
            let past = &result[else_abs + 4..];
            let ws2 = past.len() - past.trim_start().len();
            let brace_pos = else_abs + 4 + ws2;
            if brace_pos < result.len() && result.as_bytes()[brace_pos] == b'{' {
                find_brace_block(&result, brace_pos).unwrap_or(block_end)
            } else {
                block_end
            }
        } else {
            block_end
        };

        result = format!("{}{}{}", &result[..m.start()], body, &result[skip_end..]);
        changes += 1;
    }

    (result, changes)
}

fn simplify_ternary_const(source: &str) -> (String, usize) {
    static TERNARY_TRUE_RE: LazyLock<Regex> = LazyLock::new(|| {
        let branch = r#"(?:"[^"]*"|'[^']*'|[^:,;])+?"#;
        let pat = format!(r#"(?:true|!0)\s*\?\s*({branch})\s*:\s*([^,;\n]+)"#);
        Regex::new(&pat).unwrap()
    });
    static TERNARY_FALSE_RE: LazyLock<Regex> = LazyLock::new(|| {
        let branch = r#"(?:"[^"]*"|'[^']*'|[^:,;])+?"#;
        let pat = format!(r#"(?:false|!1)\s*\?\s*({branch})\s*:\s*([^,;\n]+)"#);
        Regex::new(&pat).unwrap()
    });

    let mut changes = 0;
    let result = TERNARY_TRUE_RE.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        caps[1].trim().to_string()
    });
    let mut result = result.into_owned();

    let new = TERNARY_FALSE_RE.replace_all(&result, |caps: &regex::Captures| {
        changes += 1;
        caps[2].trim().to_string()
    });
    result = new.into_owned();

    (result, changes)
}

fn simplify_logical_or_const(source: &str) -> (String, usize) {
    let mut changes = 0;

    let result = LOGICAL_OR_RE.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        caps[1].trim().to_string()
    });

    (result.into_owned(), changes)
}

fn simplify_comma_expression(source: &str) -> (String, usize) {
    let mut changes = 0;

    let result = COMMA_EXPR_RE.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        caps[1].to_string()
    });

    (result.into_owned(), changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dead_if_false() {
        let input = "if(false){ malicious(); }";
        let (output, changes) = remove_dead_if_false(input);
        assert_eq!(output.trim(), "");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_dead_if_false_with_else() {
        let input = "if(false){ dead(); } else { alive(); }";
        let (output, changes) = remove_dead_if_false(input);
        assert_eq!(output.trim(), "alive();");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_nested_braces_dead_code() {
        let input = "if(false){ if(x){ inner(); } outer(); }";
        let (output, changes) = remove_dead_if_false(input);
        assert_eq!(output.trim(), "");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_simplify_if_true() {
        let input = "if(true){ doStuff(); }";
        let (output, changes) = simplify_if_true(input);
        assert_eq!(output.trim(), "doStuff();");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_nested_braces_if_true() {
        let input = "if(true){ if(x){ inner(); } }";
        let (output, changes) = simplify_if_true(input);
        assert_eq!(output.trim(), "if(x){ inner(); }");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_ternary_true() {
        let input = "var x = true ? real : decoy;";
        let (output, changes) = simplify_ternary_const(input);
        assert_eq!(output, "var x = real;");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_comma_expression() {
        let input = "(0, eval)(code)";
        let (output, changes) = simplify_comma_expression(input);
        assert_eq!(output, "eval(code)");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_brace_block_with_comment() {
        let input = "if(false){ // } fake close\n  real(); }";
        let (output, changes) = remove_dead_if_false(input);
        assert_eq!(output.trim(), "");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_brace_block_with_block_comment() {
        let input = "if(false){ /* } */ real(); }";
        let (output, changes) = remove_dead_if_false(input);
        assert_eq!(output.trim(), "");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_brace_block_with_template_literal() {
        let input = "if(false){ var s = `${a ? {x:1} : {}}`; }";
        let (output, changes) = remove_dead_if_false(input);
        assert_eq!(output.trim(), "");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_comma_void_zero() {
        let input = "(void 0, require)(\"fs\")";
        let (output, changes) = simplify_comma_expression(input);
        assert_eq!(output, "require(\"fs\")");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_comma_undefined() {
        let input = "(undefined, eval)(code)";
        let (output, changes) = simplify_comma_expression(input);
        assert_eq!(output, "eval(code)");
        assert_eq!(changes, 1);
    }
}
