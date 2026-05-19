use regex::Regex;
use std::sync::LazyLock;

static PAREN_ARITH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(\s*(\d{1,10})\s*([+\-*/%|&^])\s*(\d{1,10})\s*\)").unwrap());
static HEX_NUM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0x([0-9a-fA-F]+)\b").unwrap());
static OCT_NUM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0o([0-7]+)\b").unwrap());
static BIN_NUM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b0b([01]+)\b").unwrap());
static TYPEOF_UNDEF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"typeof\s+undefined\s*===?\s*["']undefined["']"#).unwrap()
});
static VOID_ZERO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bvoid\s+0\b").unwrap());
static DOUBLE_BANG_EMPTY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!!\[\]").unwrap());
static DOUBLE_BANG_ONE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!!1\b").unwrap());
static DOUBLE_BANG_ZERO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!!0\b").unwrap());
static BANG_EMPTY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!\[\]").unwrap());
static PLUS_DOUBLE_BANG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\+!!\[\]").unwrap());
static PLUS_EMPTY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\+\[\]").unwrap());
static PARSE_INT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"parseInt\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*,\s*(\d{1,2})\s*\)"#).unwrap()
});
static NUMBER_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bNumber\s*\(\s*(?:(0x[0-9a-fA-F]+)|(0o[0-7]+)|(0b[01]+))\s*\)").unwrap()
});

pub fn fold(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let (s, n) = fold_string_concat(&result);
    result = s;
    total += n;

    let (s, n) = fold_cross_quote_concat(&result);
    result = s;
    total += n;

    let (s, n) = fold_parenthesized_arithmetic(&result);
    result = s;
    total += n;

    let (s, n) = normalize_number_literals(&result);
    result = s;
    total += n;

    let (s, n) = fold_parse_int(&result);
    result = s;
    total += n;

    let (s, n) = fold_number_call(&result);
    result = s;
    total += n;

    let (s, n) = fold_typeof_undefined(&result);
    result = s;
    total += n;

    let (s, n) = fold_void_zero(&result);
    result = s;
    total += n;

    let (s, n) = fold_boolean_not(&result);
    result = s;
    total += n;

    let (s, n) = fold_array_bool_tricks(&result);
    result = s;
    total += n;

    (result, total)
}

fn fold_string_concat(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    for q in ['"', '\'', '`'] {
        let qe = regex::escape(&q.to_string());
        let pat = format!(r#"{qe}([^{qe}]*){qe}\s*\+\s*{qe}([^{qe}]*){qe}"#);
        let re = Regex::new(&pat).unwrap();

        loop {
            let new = re.replace(&result, |caps: &regex::Captures| {
                total += 1;
                format!("{q}{}{}{q}", &caps[1], &caps[2])
            });
            if new == result {
                break;
            }
            result = new.into_owned();
        }
    }

    (result, total)
}

fn fold_parenthesized_arithmetic(source: &str) -> (String, usize) {
    let mut changes = 0;
    let mut result = source.to_string();

    loop {
        let new = PAREN_ARITH_RE.replace_all(&result, |caps: &regex::Captures| {
            let a: i64 = match caps[1].parse() {
                Ok(v) => v,
                Err(_) => return caps[0].to_string(),
            };
            let b: i64 = match caps[3].parse() {
                Ok(v) => v,
                Err(_) => return caps[0].to_string(),
            };
            let op = &caps[2];

            let val = match op {
                "+" => Some(a.wrapping_add(b)),
                "-" => Some(a.wrapping_sub(b)),
                "*" => Some(a.wrapping_mul(b)),
                "/" if b != 0 => Some(a / b),
                "%" if b != 0 => Some(a % b),
                "|" => Some(a | b),
                "&" => Some(a & b),
                "^" => Some(a ^ b),
                _ => None,
            };

            match val {
                Some(v) => {
                    changes += 1;
                    v.to_string()
                }
                None => caps[0].to_string(),
            }
        });
        if new == result {
            break;
        }
        result = new.into_owned();
    }

    (result, changes)
}

fn fold_cross_quote_concat(source: &str) -> (String, usize) {
    static CROSS_QUOTE_PATTERNS: LazyLock<Vec<(Regex, char)>> = LazyLock::new(|| {
        vec![
            (
                Regex::new(r#""((?:[^"\\]|\\.)*)"\s*\+\s*'((?:[^'\\]|\\.)*)'"#).unwrap(),
                '"',
            ),
            (
                Regex::new(r#"'((?:[^'\\]|\\.)*)'\s*\+\s*"((?:[^"\\]|\\.)*)""#).unwrap(),
                '\'',
            ),
        ]
    });
    let mut result = source.to_string();
    let mut total = 0;

    for (re, out_q) in CROSS_QUOTE_PATTERNS.iter() {
        let out_q = *out_q;
        loop {
            let prev = result.clone();
            let new = re.replace(&result, |caps: &regex::Captures| {
                let c2 = &caps[2];
                if c2.contains(out_q) {
                    return caps[0].to_string();
                }
                total += 1;
                format!("{out_q}{}{c2}{out_q}", &caps[1])
            });
            result = new.into_owned();
            if result == prev {
                break;
            }
        }
    }

    (result, total)
}

fn normalize_number_literals(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let new = HEX_NUM_RE.replace_all(&result, |caps: &regex::Captures| {
        match u64::from_str_radix(&caps[1], 16) {
            Ok(v) => {
                total += 1;
                v.to_string()
            }
            Err(_) => caps[0].to_string(),
        }
    });
    result = new.into_owned();

    let new = OCT_NUM_RE.replace_all(&result, |caps: &regex::Captures| {
        match u64::from_str_radix(&caps[1], 8) {
            Ok(v) => {
                total += 1;
                v.to_string()
            }
            Err(_) => caps[0].to_string(),
        }
    });
    result = new.into_owned();

    let new = BIN_NUM_RE.replace_all(&result, |caps: &regex::Captures| {
        match u64::from_str_radix(&caps[1], 2) {
            Ok(v) => {
                total += 1;
                v.to_string()
            }
            Err(_) => caps[0].to_string(),
        }
    });
    result = new.into_owned();

    (result, total)
}

/// Fold parseInt("ff", 16) → 255, parseInt("77", 8) → 63, etc.
fn fold_parse_int(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = PARSE_INT_RE.replace_all(source, |caps: &regex::Captures| {
        let digits = &caps[1];
        let radix: u32 = match caps[2].parse() {
            Ok(r) if r >= 2 && r <= 36 => r,
            _ => return caps[0].to_string(),
        };
        match u64::from_str_radix(digits, radix) {
            Ok(v) => {
                changes += 1;
                v.to_string()
            }
            Err(_) => caps[0].to_string(),
        }
    });
    (result.into_owned(), changes)
}

/// Fold Number(0xff) → 255, Number(0o77) → 63, Number(0b1010) → 10
fn fold_number_call(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = NUMBER_CALL_RE.replace_all(source, |caps: &regex::Captures| {
        let val = if let Some(hex) = caps.get(1) {
            u64::from_str_radix(&hex.as_str()[2..], 16).ok()
        } else if let Some(oct) = caps.get(2) {
            u64::from_str_radix(&oct.as_str()[2..], 8).ok()
        } else if let Some(bin) = caps.get(3) {
            u64::from_str_radix(&bin.as_str()[2..], 2).ok()
        } else {
            None
        };
        match val {
            Some(v) => {
                changes += 1;
                v.to_string()
            }
            None => caps[0].to_string(),
        }
    });
    (result.into_owned(), changes)
}

fn fold_typeof_undefined(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = TYPEOF_UNDEF_RE.replace_all(source, |_caps: &regex::Captures| {
        changes += 1;
        "true".to_string()
    });
    (result.into_owned(), changes)
}

fn fold_void_zero(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = VOID_ZERO_RE.replace_all(source, |_: &regex::Captures| {
        changes += 1;
        "undefined".to_string()
    });
    (result.into_owned(), changes)
}

fn fold_boolean_not(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let replacements: &[(&LazyLock<Regex>, &str)] = &[
        (&DOUBLE_BANG_EMPTY_RE, "true"),
        (&DOUBLE_BANG_ONE_RE, "true"),
        (&DOUBLE_BANG_ZERO_RE, "false"),
        (&BANG_EMPTY_RE, "false"),
    ];

    for (re, replacement) in replacements {
        let rep = replacement.to_string();
        let new = re.replace_all(&result, |_: &regex::Captures| {
            total += 1;
            rep.clone()
        });
        result = new.into_owned();
    }

    for (val, rep_str) in [("0", "true"), ("1", "false")] {
        let mut out = String::with_capacity(result.len());
        let chars: Vec<char> = result.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '!' && i + 1 < chars.len() && chars[i + 1].to_string() == val {
                let preceded_ok = i == 0 || !chars[i - 1].is_alphanumeric();
                let followed_ok = i + 2 >= chars.len() || !chars[i + 2].is_alphanumeric();
                if preceded_ok && followed_ok && (i == 0 || chars[i - 1] != '!') {
                    out.push_str(rep_str);
                    total += 1;
                    i += 2;
                    continue;
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        result = out;
    }

    (result, total)
}

fn fold_array_bool_tricks(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let new = PLUS_DOUBLE_BANG_RE.replace_all(&result, |_: &regex::Captures| {
        total += 1;
        "+1".to_string()
    });
    result = new.into_owned();

    let new = PLUS_EMPTY_RE.replace_all(&result, |_: &regex::Captures| {
        total += 1;
        "+0".to_string()
    });
    result = new.into_owned();

    (result, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_concat() {
        let input = r#"var x = "hel" + "lo";"#;
        let (output, changes) = fold_string_concat(input);
        assert_eq!(output, r#"var x = "hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_chained_concat() {
        let input = r#"var x = "a" + "b" + "c";"#;
        let (output, _) = fold_string_concat(input);
        assert_eq!(output, r#"var x = "abc";"#);
    }

    #[test]
    fn test_paren_arithmetic() {
        let input = "var x = (2 + 3);";
        let (output, changes) = fold_parenthesized_arithmetic(input);
        assert_eq!(output, "var x = 5;");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_no_precedence_break() {
        let input = "var x = 2 + 3 * 4;";
        let (output, changes) = fold_parenthesized_arithmetic(input);
        assert_eq!(output, "var x = 2 + 3 * 4;");
        assert_eq!(changes, 0);
    }

    #[test]
    fn test_nested_paren_arithmetic() {
        let input = "var x = ((2 + 3) * 4);";
        let (output, _) = fold_parenthesized_arithmetic(input);
        assert_eq!(output, "var x = 20;");
    }

    #[test]
    fn test_void_zero() {
        let input = "if (x === void 0) {}";
        let (output, changes) = fold_void_zero(input);
        assert_eq!(output, "if (x === undefined) {}");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_boolean_not() {
        let input = "var x = !0; var y = !1;";
        let (output, _) = fold_boolean_not(input);
        assert_eq!(output, "var x = true; var y = false;");
    }

    #[test]
    fn test_return_bang_zero() {
        let input = "return !0";
        let (output, _) = fold_boolean_not(input);
        assert_eq!(output, "return true");
    }

    #[test]
    fn test_parse_int_hex() {
        let input = r#"var x = parseInt("ff", 16);"#;
        let (output, changes) = fold_parse_int(input);
        assert_eq!(output, "var x = 255;");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_parse_int_octal() {
        let input = r#"var x = parseInt("77", 8);"#;
        let (output, changes) = fold_parse_int(input);
        assert_eq!(output, "var x = 63;");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_number_call() {
        let input = "var x = Number(0xff);";
        let (output, changes) = fold_number_call(input);
        assert_eq!(output, "var x = 255;");
        assert_eq!(changes, 1);
    }
}
