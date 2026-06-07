use regex::Regex;

pub fn unwrap(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;

    let (s, n) = unwrap_eval_string(&result);
    result = s;
    total += n;

    let (s, n) = unwrap_function_constructor(&result);
    result = s;
    total += n;

    let (s, n) = unwrap_settimeout_string(&result);
    result = s;
    total += n;

    let (s, n) = unwrap_setinterval_string(&result);
    result = s;
    total += n;

    (result, total)
}

fn unwrap_eval_quoted(source: &str, quote: char) -> (String, usize) {
    let q = regex::escape(&quote.to_string());
    let pat = format!(r#"eval\s*\(\s*{q}((?:[^{q}\\]|\\.)+){q}\s*\)"#);
    let re = Regex::new(&pat).unwrap();
    let mut changes = 0;

    let result = re.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        format!("/* vigil:eval */ {}", &caps[1])
    });

    (result.into_owned(), changes)
}

fn unwrap_eval_string(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;
    for q in ['"', '\'', '`'] {
        let (s, n) = unwrap_eval_quoted(&result, q);
        result = s;
        total += n;
    }
    (result, total)
}

fn unwrap_func_quoted(source: &str, quote: char) -> (String, usize) {
    let q = regex::escape(&quote.to_string());
    let pat = format!(r#"new\s+Function\s*\(\s*{q}((?:[^{q}\\]|\\.)+){q}\s*\)(?:\s*\(\s*\))?"#);
    let re = Regex::new(&pat).unwrap();
    let mut changes = 0;

    let result = re.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        format!("/* vigil:Function */ {}", &caps[1])
    });

    (result.into_owned(), changes)
}

fn unwrap_function_constructor(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;
    for q in ['"', '\'', '`'] {
        let (s, n) = unwrap_func_quoted(&result, q);
        result = s;
        total += n;
    }
    (result, total)
}

fn unwrap_timeout_quoted(source: &str, quote: char) -> (String, usize) {
    let q = regex::escape(&quote.to_string());
    let pat = format!(r#"setTimeout\s*\(\s*{q}((?:[^{q}\\]|\\.)+){q}\s*,\s*(\d+)\s*\)"#);
    let re = Regex::new(&pat).unwrap();
    let mut changes = 0;

    let result = re.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        format!(
            "setTimeout(function(){{ /* vigil:timeout */ {} }}, {})",
            &caps[1], &caps[2]
        )
    });

    (result.into_owned(), changes)
}

fn unwrap_settimeout_string(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;
    for q in ['"', '\'', '`'] {
        let (s, n) = unwrap_timeout_quoted(&result, q);
        result = s;
        total += n;
    }
    (result, total)
}

fn unwrap_interval_quoted(source: &str, quote: char) -> (String, usize) {
    let q = regex::escape(&quote.to_string());
    let pat = format!(r#"setInterval\s*\(\s*{q}((?:[^{q}\\]|\\.)+){q}\s*,\s*(\d+)\s*\)"#);
    let re = Regex::new(&pat).unwrap();
    let mut changes = 0;

    let result = re.replace_all(source, |caps: &regex::Captures| {
        changes += 1;
        format!(
            "setInterval(function(){{ /* vigil:interval */ {} }}, {})",
            &caps[1], &caps[2]
        )
    });

    (result.into_owned(), changes)
}

fn unwrap_setinterval_string(source: &str) -> (String, usize) {
    let mut result = source.to_string();
    let mut total = 0;
    for q in ['"', '\'', '`'] {
        let (s, n) = unwrap_interval_quoted(&result, q);
        result = s;
        total += n;
    }
    (result, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_unwrap() {
        let input = r#"eval("console.log('pwned')");"#;
        let (output, changes) = unwrap_eval_string(input);
        assert_eq!(output, r#"/* vigil:eval */ console.log('pwned');"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_function_constructor() {
        let input = r#"var f = new Function("return 42")();"#;
        let (output, changes) = unwrap_function_constructor(input);
        assert_eq!(output, r#"var f = /* vigil:Function */ return 42;"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_settimeout_unwrap() {
        let input = r#"setTimeout("alert(1)", 100);"#;
        let (output, changes) = unwrap_settimeout_string(input);
        assert_eq!(output, r#"setTimeout(function(){ /* vigil:timeout */ alert(1) }, 100);"#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_eval_escaped_quotes() {
        let input = r#"eval("say \"hi\"")"#;
        let (output, changes) = unwrap_eval_string(input);
        assert_eq!(output, r#"/* vigil:eval */ say \"hi\""#);
        assert_eq!(changes, 1);
    }

    #[test]
    fn test_setinterval_unwrap() {
        let input = r#"setInterval("ping()", 5000);"#;
        let (output, changes) = unwrap_setinterval_string(input);
        assert_eq!(output, r#"setInterval(function(){ /* vigil:interval */ ping() }, 5000);"#);
        assert_eq!(changes, 1);
    }
}
