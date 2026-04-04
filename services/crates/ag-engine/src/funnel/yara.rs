//! YARA rule integration via yara-x (VirusTotal's pure Rust engine).
//! Scans decoded binary content for executable signatures, shellcode, etc.

/// A YARA rule match result.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub category: String,
    pub risk_score: f64,
}

/// YARA scanner — loads and compiles rules, scans binary content.
pub struct YaraScanner {
    rules: yara_x::Rules,
}

impl YaraScanner {
    /// Load and compile built-in YARA rules from embedded .yar files.
    pub fn with_builtins() -> Self {
        let mut compiler = yara_x::Compiler::new();

        let yar_sources: &[(&str, &str)] = &[
            ("executables.yar", include_str!("../builtins/yara/executables.yar")),
            ("scripts.yar", include_str!("../builtins/yara/scripts.yar")),
            ("exfil.yar", include_str!("../builtins/yara/exfil.yar")),
        ];

        for (filename, source) in yar_sources {
            if let Err(e) = compiler.add_source(source.as_bytes()) {
                tracing::warn!(file = %filename, error = %e, "Failed to compile YARA rules");
            }
        }

        let rules = compiler.build();

        Self { rules }
    }

    /// Number of compiled YARA rules.
    pub fn rule_count(&self) -> usize {
        self.rules.iter().count()
    }

    /// Scan binary content against compiled YARA rules.
    pub fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let scan_results = match scanner.scan(data) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "YARA scan failed");
                return Vec::new();
            }
        };

        scan_results
            .matching_rules()
            .map(|rule| {
                let mut category = "unknown".to_string();
                let mut risk_score = 0.80_f64;

                for (key, value) in rule.metadata() {
                    match key {
                        "category" => {
                            if let yara_x::MetaValue::String(s) = value {
                                category = s.to_string();
                            }
                        }
                        "risk_score" => {
                            if let yara_x::MetaValue::String(s) = value {
                                if let Ok(v) = s.parse::<f64>() {
                                    risk_score = v;
                                }
                            }
                        }
                        _ => {}
                    }
                }

                YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    category,
                    risk_score,
                }
            })
            .collect()
    }
}
