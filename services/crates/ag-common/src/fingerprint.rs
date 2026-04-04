//! Hardware fingerprint for license binding.
//!
//! Generates a deterministic fingerprint from machine characteristics.
//! The license server can optionally bind a license to a specific fingerprint
//! to prevent reuse across multiple deployments.
//!
//! Fingerprint = SHA256(machine_id + hostname + cpu_count + total_memory_gb)
//!
//! In Docker/K8s, `machine_id` comes from the host (mounted or env var).
//! Falls back to container hostname if host ID is unavailable.

use sha2::{Digest, Sha256};
use std::fmt;

/// Hardware fingerprint result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// SHA-256 hex string (64 chars).
    pub hash: String,
    /// Components used to generate the fingerprint (for debugging).
    pub components: Vec<(String, String)>,
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hash)
    }
}

/// Generate the machine fingerprint.
///
/// Components (in order):
/// 1. Machine ID: /etc/machine-id, CLAMPD_MACHINE_ID env, or hostname fallback
/// 2. Hostname
/// 3. CPU count
/// 4. Total memory in GB (rounded)
pub fn generate() -> Fingerprint {
    let mut components = Vec::new();

    // 1. Machine ID
    let machine_id = get_machine_id();
    components.push(("machine_id".to_string(), machine_id.clone()));

    // 2. Hostname
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string());
    components.push(("hostname".to_string(), hostname.clone()));

    // 3. CPU count
    let cpus = num_cpus().to_string();
    components.push(("cpus".to_string(), cpus.clone()));

    // 4. Total memory (GB, rounded)
    let mem_gb = total_memory_gb().to_string();
    components.push(("memory_gb".to_string(), mem_gb.clone()));

    // Hash all components
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"|");
    hasher.update(hostname.as_bytes());
    hasher.update(b"|");
    hasher.update(cpus.as_bytes());
    hasher.update(b"|");
    hasher.update(mem_gb.as_bytes());

    let hash = format!("{:x}", hasher.finalize());

    Fingerprint { hash, components }
}

/// Validate that the current machine matches the expected fingerprint.
/// Returns true if fingerprint is empty (no binding) or matches.
pub fn validate(expected: &str) -> bool {
    if expected.is_empty() {
        return true; // No fingerprint binding
    }
    let current = generate();
    current.hash == expected
}

/// Get machine ID from multiple sources.
fn get_machine_id() -> String {
    // 1. Explicit env var (for Docker/K8s where host ID is mounted)
    if let Ok(id) = std::env::var("CLAMPD_MACHINE_ID") {
        if !id.is_empty() {
            return id;
        }
    }

    // 2. /etc/machine-id (Linux standard)
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    // 3. /var/lib/dbus/machine-id (fallback on some distros)
    if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    // 4. Fallback to hostname
    std::env::var("HOSTNAME").unwrap_or_else(|_| "no-machine-id".to_string())
}

/// Get CPU count.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Get total memory in GB (rounded). Reads from /proc/meminfo on Linux.
fn total_memory_gb() -> u64 {
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                // Format: "MemTotal:       16384000 kB"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb / 1_048_576; // KB to GB (rounded down)
                    }
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_deterministic() {
        let fp1 = generate();
        let fp2 = generate();
        assert_eq!(fp1.hash, fp2.hash);
        assert_eq!(fp1.hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_validate_empty_fingerprint() {
        assert!(validate("")); // No binding = always valid
    }

    #[test]
    fn test_validate_wrong_fingerprint() {
        assert!(!validate("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_validate_correct_fingerprint() {
        let fp = generate();
        assert!(validate(&fp.hash));
    }
}
