use regex::Regex;
use std::sync::LazyLock;

static HEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap());
static UNI_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap());
static ES6_UNI_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\u\{([0-9a-fA-F]{1,6})\}").unwrap());
static CHAR_CODE_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\[(\s*\d{1,5}\s*(?:,\s*\d{1,5}\s*){2,})\]\.map\s*\(\s*(?:\w*\s*=>\s*String\.fromCharCode\s*\(\s*\w*\s*\)|function\s*\(\w*\)\s*\{\s*return\s+String\.fromCharCode\s*\(\s*\w*\s*\)\s*;?\s*\}|String\.fromCharCode)\s*\)\.join\s*\(\s*["'`]["'`]\s*\)"#,
    )
    .unwrap()
});
static ATOB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:(?:window|self|globalThis)\.)?atob\s*\(\s*["'`]([A-Za-z0-9+/=]+)["'`]\s*\)"#)
        .unwrap()
});
static FROM_CHAR_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"String\.fromCharCode\s*\((\s*\d{1,5}\s*(?:,\s*\d{1,5}\s*){1,})"#).unwrap()
});
static FROM_CHAR_CODE_APPLY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"String\.fromCharCode\s*\.\s*apply\s*\(\s*(?:null|undefined|this|window|globalThis|self)?\s*,\s*\[(\s*\d{1,5}\s*(?:,\s*\d{1,5}\s*)*)\]\s*\)"#,
    )
    .unwrap()
});
static FROM_CHAR_CODE_SPREAD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"String\.fromCharCode\s*\(\s*\.\.\.\s*\[(\s*\d{1,5}\s*(?:,\s*\d{1,5}\s*)*)\]\s*\)"#).unwrap()
});
static BUFFER_BASE64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"Buffer\.from\s*\(\s*["']([A-Za-z0-9+/=]+)["']\s*,\s*["']base64["']\s*\)\.toString\s*\(\s*\)"#,
    )
    .unwrap()
});
static SPLIT_REVERSE_JOIN_DQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([^"]{2,})"\.split\s*\(\s*""\s*\)\.reverse\s*\(\s*\)\.join\s*\(\s*""\s*\)"#)
        .unwrap()
});
static SPLIT_REVERSE_JOIN_SQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"'([^']{2,})'\.split\s*\(\s*''\s*\)\.reverse\s*\(\s*\)\.join\s*\(\s*''\s*\)"#)
        .unwrap()
});

pub fn decode_all(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let (s, n) = decode_mixed_hex_escapes(&result);
    result = s;
    total += n;

    let (s, n) = decode_mixed_unicode_escapes(&result);
    result = s;
    total += n;

    let (s, n) = decode_es6_unicode(&result);
    result = s;
    total += n;

    let (s, n) = decode_char_code_array(&result);
    result = s;
    total += n;

    let (s, n) = decode_atob_literals(&result);
    result = s;
    total += n;

    let (s, n) = decode_from_char_code(&result);
    result = s;
    total += n;

    let (s, n) = decode_from_char_code_apply(&result);
    result = s;
    total += n;

    let (s, n) = decode_from_char_code_spread(&result);
    result = s;
    total += n;

    let (s, n) = decode_buffer_from_base64(&result);
    result = s;
    total += n;

    let (s, n) = decode_split_reverse_join(&result);
    result = s;
    total += n;

    let (s, n) = decode_concat_calls(&result);
    result = s;
    total += n;

    (result, total)
}

fn decode_mixed_hex_escapes(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    for quote in ['"', '\'', '`'] {
        let qe = regex::escape(&quote.to_string());
        let pat = format!(r#"{qe}((?:[^{qe}\\]|\\.)*){qe}"#);
        let re = match Regex::new(&pat) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let new = re.replace_all(&result, |caps: &regex::Captures| {
            let inner = &caps[1];
            if !HEX_RE.is_match(inner) {
                return caps[0].to_string();
            }
            let decoded = HEX_RE.replace_all(inner, |hcaps: &regex::Captures| {
                match u8::from_str_radix(&hcaps[1], 16) {
                    Ok(b) => {
                        let c = b as char;
                        if c == '\\' || c == quote {
                            return hcaps[0].to_string();
                        }
                        if c.is_ascii_graphic() || matches!(c, ' ' | '\t' | '\n' | '\r') {
                            c.to_string()
                        } else {
                            hcaps[0].to_string()
                        }
                    }
                    _ => hcaps[0].to_string(),
                }
            });
            if decoded != inner {
                total += 1;
                format!("{quote}{decoded}{quote}")
            } else {
                caps[0].to_string()
            }
        });
        result = new.into_owned();
    }

    (result, total)
}

fn decode_mixed_unicode_escapes(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    for quote in ['"', '\''] {
        let qe = regex::escape(&quote.to_string());
        let pat = format!(r#"{qe}((?:[^{qe}\\]|\\.)*){qe}"#);
        let re = match Regex::new(&pat) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let new = re.replace_all(&result, |caps: &regex::Captures| {
            let inner = &caps[1];
            if !UNI_RE.is_match(inner) {
                return caps[0].to_string();
            }
            let decoded = UNI_RE.replace_all(inner, |ucaps: &regex::Captures| {
                match u32::from_str_radix(&ucaps[1], 16).ok().and_then(char::from_u32) {
                    Some(c) if c == '\\' || c == quote => ucaps[0].to_string(),
                    Some(c) if c.is_ascii_graphic() || matches!(c, ' ' | '\t' | '\n' | '\r') => {
                        c.to_string()
                    }
                    _ => ucaps[0].to_string(),
                }
            });
            if decoded != inner {
                total += 1;
                format!("{quote}{decoded}{quote}")
            } else {
                caps[0].to_string()
            }
        });
        result = new.into_owned();
    }

    (result, total)
}

fn decode_es6_unicode(source: &str) -> (String, usize) {
    let mut total = 0;
    let mut result = source.to_string();

    for quote in ['"', '\''] {
        let qe = regex::escape(&quote.to_string());
        let pat = format!(r#"{qe}([^{qe}]*\\u\{{[0-9a-fA-F]{{1,6}}\}}[^{qe}]*){qe}"#);
        let re = match Regex::new(&pat) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let new = re.replace_all(&result, |caps: &regex::Captures| {
            let inner = &caps[1];
            let decoded = ES6_UNI_RE.replace_all(inner, |ucaps: &regex::Captures| {
                match u32::from_str_radix(&ucaps[1], 16).ok().and_then(char::from_u32) {
                    Some(c) if c == '\\' || c == quote => ucaps[0].to_string(),
                    Some(c) if c.is_ascii_graphic() || matches!(c, ' ' | '\t' | '\n' | '\r') => {
                        total += 1;
                        c.to_string()
                    }
                    _ => ucaps[0].to_string(),
                }
            });
            if decoded != inner {
                format!("{quote}{decoded}{quote}")
            } else {
                caps[0].to_string()
            }
        });
        result = new.into_owned();
    }

    (result, total)
}

fn decode_char_code_array(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = CHAR_CODE_ARRAY_RE.replace_all(source, |caps: &regex::Captures| {
        let nums_str = &caps[1];
        let decoded: String = nums_str
            .split(',')
            .filter_map(|n| n.trim().parse::<u32>().ok().and_then(char::from_u32))
            .collect();

        if !decoded.is_empty() && decoded.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            changes += 1;
            format!("\"{decoded}\"")
        } else {
            caps[0].to_string()
        }
    });

    (result.into_owned(), changes)
}

fn decode_atob_literals(source: &str) -> (String, usize) {
    let mut changes = 0;

    let result = ATOB_RE.replace_all(source, |caps: &regex::Captures| {
        let b64 = &caps[1];
        match base64_decode(b64) {
            Some(decoded)
                if decoded
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) =>
            {
                changes += 1;
                let escaped = decoded.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{escaped}\"")
            }
            _ => caps[0].to_string(),
        }
    });

    (result.into_owned(), changes)
}

fn decode_from_char_code(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = FROM_CHAR_CODE_RE.replace_all(source, |caps: &regex::Captures| {
        let nums_str = &caps[1];
        let decoded: String = nums_str
            .split(',')
            .filter_map(|n| n.trim().parse::<u32>().ok().and_then(char::from_u32))
            .collect();

        if !decoded.is_empty() && decoded.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            changes += 1;
            format!("\"{decoded}\"")
        } else {
            caps[0].to_string()
        }
    });

    (result.into_owned(), changes)
}

fn char_codes_to_string(nums_str: &str) -> Option<String> {
    let decoded: String = nums_str
        .split(',')
        .filter_map(|n| n.trim().parse::<u32>().ok().and_then(char::from_u32))
        .collect();

    if !decoded.is_empty() && decoded.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        Some(decoded)
    } else {
        None
    }
}

/// Fold String.fromCharCode.apply(null, [97, 98, 99]) → "abc"
fn decode_from_char_code_apply(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = FROM_CHAR_CODE_APPLY_RE.replace_all(source, |caps: &regex::Captures| {
        match char_codes_to_string(&caps[1]) {
            Some(decoded) => {
                changes += 1;
                format!("\"{decoded}\"")
            }
            None => caps[0].to_string(),
        }
    });

    (result.into_owned(), changes)
}

/// Fold String.fromCharCode(...[97, 98, 99]) → "abc"
fn decode_from_char_code_spread(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = FROM_CHAR_CODE_SPREAD_RE.replace_all(source, |caps: &regex::Captures| {
        match char_codes_to_string(&caps[1]) {
            Some(decoded) => {
                changes += 1;
                format!("\"{decoded}\"")
            }
            None => caps[0].to_string(),
        }
    });

    (result.into_owned(), changes)
}

fn decode_buffer_from_base64(source: &str) -> (String, usize) {
    let mut changes = 0;
    let result = BUFFER_BASE64_RE.replace_all(source, |caps: &regex::Captures| {
        match base64_decode(&caps[1]) {
            Some(decoded)
                if decoded
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) =>
            {
                changes += 1;
                let escaped = decoded.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{escaped}\"")
            }
            _ => caps[0].to_string(),
        }
    });

    (result.into_owned(), changes)
}

/// Decode "cba".split("").reverse().join("") → "abc"
fn decode_split_reverse_join(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    for (re, q) in [(&*SPLIT_REVERSE_JOIN_DQ_RE, '"'), (&*SPLIT_REVERSE_JOIN_SQ_RE, '\'')] {
        let new = re.replace_all(&result, |caps: &regex::Captures| {
            let content = &caps[1];
            let reversed: String = content.chars().rev().collect();
            if reversed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                total += 1;
                format!("{q}{reversed}{q}")
            } else {
                caps[0].to_string()
            }
        });
        result = new.into_owned();
    }

    (result, total)
}

/// Fold "a".concat("b", "c") → "abc"
fn decode_concat_calls(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    for q in ['"', '\''] {
        loop {
            let prev = result.clone();
            let new = fold_one_concat(&result, q);
            if new == prev {
                break;
            }
            total += 1;
            result = new;
        }
    }

    (result, total)
}

fn fold_one_concat(source: &str, q: char) -> String {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let qb = q as u8;
    let mut i = 0;

    while i < len {
        // Find a quoted string: look for q...q.concat(
        if bytes[i] != qb {
            i += 1;
            continue;
        }
        let str_start = i;
        i += 1;
        // scan to closing quote, handling escapes
        while i < len {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == qb {
                break;
            }
            i += 1;
        }
        if i >= len {
            break;
        }
        let str_end = i + 1; // past closing quote
        i = str_end;

        // Check for .concat(
        let rest = &source[i..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with(".concat") {
            continue;
        }
        let skip_ws = rest.len() - trimmed.len();
        let after_concat = &trimmed[7..]; // skip ".concat"
        let after_trim = after_concat.trim_start();
        if !after_trim.starts_with('(') {
            continue;
        }
        let paren_start = i + skip_ws + 7 + (after_concat.len() - after_trim.len());

        // Parse arguments inside concat(...)
        let mut args: Vec<String> = Vec::new();
        let mut j = paren_start + 1; // skip '('
        let mut valid = true;

        loop {
            // skip whitespace
            while j < len && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r') {
                j += 1;
            }
            if j >= len {
                valid = false;
                break;
            }
            if bytes[j] == b')' {
                j += 1;
                break;
            }
            // expect a quoted string argument
            if bytes[j] != qb {
                valid = false;
                break;
            }
            j += 1;
            let arg_start = j;
            while j < len {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == qb {
                    break;
                }
                j += 1;
            }
            if j >= len {
                valid = false;
                break;
            }
            args.push(source[arg_start..j].to_string());
            j += 1; // skip closing quote

            // skip whitespace, then comma or closing paren
            while j < len && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r') {
                j += 1;
            }
            if j < len && bytes[j] == b',' {
                j += 1;
            }
        }

        if !valid || args.is_empty() {
            continue;
        }

        let base_content = &source[str_start + 1..str_end - 1];
        let mut merged = base_content.to_string();
        for arg in &args {
            merged.push_str(arg);
        }
        return format!("{}{q}{merged}{q}{}", &source[..str_start], &source[j..]);
    }

    source.to_string()
}

fn base64_decode(input: &str) -> Option<String> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::new();
    let chars: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();

    for chunk in chars.chunks(4) {
        let sextet: Vec<u8> = chunk
            .iter()
            .filter_map(|&b| table.iter().position(|&t| t == b).map(|p| p as u8))
            .collect();

        if sextet.len() >= 2 {
            bytes.push((sextet[0] << 2) | (sextet[1] >> 4));
        }
        if sextet.len() >= 3 {
            bytes.push((sextet[1] << 4) | (sextet[2] >> 2));
        }
        if sextet.len() >= 4 {
            bytes.push((sextet[2] << 6) | sextet[3]);
        }
    }

    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        let input = r#"var x = "\x48\x65\x6c\x6c\x6f";"#;
        let (output, changes) = decode_mixed_hex_escapes(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_mixed_hex_decode() {
        let input = r#"var x = "\x48ello\x21";"#;
        let (output, changes) = decode_mixed_hex_escapes(input);
        assert_eq!(output, r#"var x = "Hello!";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_unicode_decode() {
        let input = "var x = \"\\u0048\\u0065\\u006c\\u006c\\u006f\";";
        let (output, changes) = decode_mixed_unicode_escapes(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_es6_unicode() {
        let input = r#"var x = "\u{48}\u{65}\u{6c}\u{6c}\u{6f}";"#;
        let (output, changes) = decode_es6_unicode(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 5);
    }

    #[test]
    fn test_atob_decode() {
        let input = r#"var x = atob("SGVsbG8gV29ybGQ=");"#;
        let (output, changes) = decode_atob_literals(input);
        assert_eq!(output, r#"var x = "Hello World";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_from_char_code() {
        let input = r#"var x = String.fromCharCode(72, 101, 108, 108, 111);"#;
        let (output, changes) = decode_from_char_code(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_from_char_code_two_args() {
        let input = r#"var x = String.fromCharCode(72, 101);"#;
        let (output, changes) = decode_from_char_code(input);
        assert_eq!(output, r#"var x = "He";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_char_code_array() {
        let input =
            r#"var x = [72,101,108,108,111].map(c => String.fromCharCode(c)).join("");"#;
        let (output, changes) = decode_char_code_array(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_buffer_from_base64() {
        let input = r#"var x = Buffer.from("Y2hpbGRfcHJvY2Vzcw==", "base64").toString();"#;
        let (output, changes) = decode_buffer_from_base64(input);
        assert_eq!(output, r#"var x = "child_process";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_split_reverse_join() {
        let input = r#"var x = "dlrow".split("").reverse().join("");"#;
        let (output, changes) = decode_split_reverse_join(input);
        assert_eq!(output, r#"var x = "world";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_concat_two_args() {
        let input = r#"var x = "hel".concat("lo");"#;
        let (output, changes) = decode_concat_calls(input);
        assert_eq!(output, r#"var x = "hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_concat_multi_args() {
        let input = r#"var x = "a".concat("b", "c", "d");"#;
        let (output, changes) = decode_concat_calls(input);
        assert_eq!(output, r#"var x = "abcd";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_concat_chained() {
        let input = r#"var x = "a".concat("b").concat("c");"#;
        let (output, changes) = decode_concat_calls(input);
        assert_eq!(output, r#"var x = "abc";"#);
        assert_eq!(changes, 2);
    }

    #[test]
    fn test_concat_single_quotes() {
        let input = "var x = 'return '.concat('process.env');";
        let (output, changes) = decode_concat_calls(input);
        assert_eq!(output, "var x = 'return process.env';");
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_from_char_code_apply() {
        let input = r#"var x = String.fromCharCode.apply(null, [72, 101, 108, 108, 111]);"#;
        let (output, changes) = decode_from_char_code_apply(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_from_char_code_spread() {
        let input = r#"var x = String.fromCharCode(...[72, 101, 108, 108, 111]);"#;
        let (output, changes) = decode_from_char_code_spread(input);
        assert_eq!(output, r#"var x = "Hello";"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_from_char_code_apply_thisarg() {
        let input = r#"var x = String.fromCharCode.apply(this, [72, 101]);"#;
        let (output, changes) = decode_from_char_code_apply(input);
        assert_eq!(output, r#"var x = "He";"#);
        assert_eq!(changes, 1);
    }
}
