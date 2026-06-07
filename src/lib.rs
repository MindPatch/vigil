//! Vigil — deobfuscation-first supply chain attack detector for JavaScript/npm.
//!
//! This library crate exposes the analysis engine so it can be embedded and
//! tested directly. The `vigil` binary (src/main.rs) is a thin CLI on top.

pub mod config;
pub mod deobfuscator;
pub mod engine;
pub mod manifest;
pub mod monitor;
pub mod parser;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod webhook;
