//! Magic byte detection - identify file types from byte content.

/// Detected file type from magic bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicType {
    PE,
    ELF,
    MachO,
    JavaClass,
    ZIP,
    GZIP,
    PDF,
    Script(String),
    Unknown,
}

/// Detect the file type from the first bytes of content.
pub fn detect(data: &[u8]) -> MagicType {
    if data.len() < 2 {
        return MagicType::Unknown;
    }

    match data {
        [0x4D, 0x5A, ..] => MagicType::PE,
        [0x7F, 0x45, 0x4C, 0x46, ..] => MagicType::ELF,
        [0xCE, 0xFA, 0xED, 0xFE, ..] | [0xCF, 0xFA, 0xED, 0xFE, ..] => MagicType::MachO,
        [0xCA, 0xFE, 0xBA, 0xBE, ..] => MagicType::JavaClass,
        [0x50, 0x4B, 0x03, 0x04, ..] => MagicType::ZIP,
        [0x1F, 0x8B, ..] => MagicType::GZIP,
        [0x25, 0x50, 0x44, 0x46, ..] => MagicType::PDF, // %PDF
        _ => {
            // Check for script shebangs
            if data.starts_with(b"#!/") {
                let first_line = data.iter()
                    .position(|&b| b == b'\n')
                    .map(|pos| &data[..pos])
                    .unwrap_or(&data[..data.len().min(80)]);
                let shebang = String::from_utf8_lossy(first_line);
                if shebang.contains("bash") || shebang.contains("/sh") {
                    MagicType::Script("bash".to_string())
                } else if shebang.contains("python") {
                    MagicType::Script("python".to_string())
                } else if shebang.contains("node") {
                    MagicType::Script("node".to_string())
                } else if shebang.contains("perl") {
                    MagicType::Script("perl".to_string())
                } else if shebang.contains("ruby") {
                    MagicType::Script("ruby".to_string())
                } else {
                    MagicType::Script("unknown".to_string())
                }
            } else {
                MagicType::Unknown
            }
        }
    }
}
