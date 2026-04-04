// Copyright (c) 2026 Clampd Inc. - BUSL-1.1
// Rule definitions loaded from embedded TOML at compile time.

use crate::parse::ParsedRule;
use crate::compile::CompiledRuleset;

pub fn load_builtin_rules() -> Vec<ParsedRule> {
    Vec::new()
}

pub fn compile_builtins() -> CompiledRuleset {
    let rules = load_builtin_rules();
    let scheme = crate::scheme::clampd_scheme();
    CompiledRuleset::compile(rules, &scheme)
        .expect("built-in rules must compile")
}
