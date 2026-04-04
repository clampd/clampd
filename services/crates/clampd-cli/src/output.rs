use serde::Serialize;
use tabled::{Table, Tabled};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Plain,
}

impl OutputFormat {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            "plain" => Self::Plain,
            _ => Self::Table,
        }
    }
}

/// Print a list of items as a table, JSON array, or plain text.
pub fn print_list<T: Tabled + Serialize>(items: &[T], format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            if items.is_empty() {
                println!("No results.");
            } else {
                let table = Table::new(items).to_string();
                println!("{table}");
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(items).unwrap_or_default();
            println!("{json}");
        }
        OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(items).unwrap_or_default();
            println!("{json}");
        }
    }
}

/// Print a single item as a table, JSON, or plain text.
pub fn print_one<T: Tabled + Serialize>(item: &T, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            let table = Table::new(std::iter::once(item)).to_string();
            println!("{table}");
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(item).unwrap_or_default();
            println!("{json}");
        }
        OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(item).unwrap_or_default();
            println!("{json}");
        }
    }
}

/// Print a success message.
pub fn print_success(msg: &str) {
    println!("OK: {msg}");
}

/// Print a warning message.
pub fn print_warn(msg: &str) {
    eprintln!("WARN: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_loose_json() {
        assert_eq!(OutputFormat::from_str_loose("json"), OutputFormat::Json);
    }

    #[test]
    fn from_str_loose_json_uppercase() {
        assert_eq!(OutputFormat::from_str_loose("JSON"), OutputFormat::Json);
    }

    #[test]
    fn from_str_loose_plain() {
        assert_eq!(OutputFormat::from_str_loose("plain"), OutputFormat::Plain);
    }

    #[test]
    fn from_str_loose_table_explicit() {
        assert_eq!(OutputFormat::from_str_loose("table"), OutputFormat::Table);
    }

    #[test]
    fn from_str_loose_unknown_defaults_to_table() {
        assert_eq!(OutputFormat::from_str_loose("csv"), OutputFormat::Table);
        assert_eq!(OutputFormat::from_str_loose(""), OutputFormat::Table);
        assert_eq!(OutputFormat::from_str_loose("yaml"), OutputFormat::Table);
    }

    #[test]
    fn from_str_loose_mixed_case() {
        assert_eq!(OutputFormat::from_str_loose("Json"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str_loose("PLAIN"), OutputFormat::Plain);
    }

    #[test]
    fn output_format_eq() {
        assert_eq!(OutputFormat::Table, OutputFormat::Table);
        assert_ne!(OutputFormat::Table, OutputFormat::Json);
        assert_ne!(OutputFormat::Json, OutputFormat::Plain);
    }
}
