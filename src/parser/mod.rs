use std::path::Path;
use tree_sitter::{Parser, Tree};

pub enum JsDialect {
    JavaScript,
    TypeScript,
    Tsx,
}

pub fn detect_dialect(path: &Path) -> Option<JsDialect> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("js" | "mjs" | "cjs" | "jsx") => Some(JsDialect::JavaScript),
        Some("ts" | "mts" | "cts") => Some(JsDialect::TypeScript),
        Some("tsx") => Some(JsDialect::Tsx),
        _ => None,
    }
}

pub fn parse_js(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = tree_sitter_javascript::LANGUAGE;
    parser.set_language(&language.into()).ok()?;
    parser.parse(source, None)
}

pub fn parse_typescript(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT;
    parser.set_language(&language.into()).ok()?;
    parser.parse(source, None)
}

pub fn parse_tsx(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = tree_sitter_typescript::LANGUAGE_TSX;
    parser.set_language(&language.into()).ok()?;
    parser.parse(source, None)
}

pub fn parse_auto(source: &str, path: &Path) -> Option<Tree> {
    match detect_dialect(path) {
        Some(JsDialect::TypeScript) => parse_typescript(source),
        Some(JsDialect::Tsx) => parse_tsx(source),
        Some(JsDialect::JavaScript) => parse_js(source),
        None => None,
    }
}
