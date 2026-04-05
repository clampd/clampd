use serde::{Deserialize, Serialize};

/// Per-stage degradation config: what to do when an upstream service is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationConfig {
    pub intent_unavailable: DegradationMode,
    pub policy_unavailable: DegradationMode,
    pub token_broker_unavailable: DegradationMode,
    pub registry_unavailable: DegradationMode,
    pub nats_unavailable: NatsFailureMode,
    pub session_unavailable: SessionFailureMode,
    pub audit_strict: bool,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        Self {
            intent_unavailable: DegradationMode::FailClosed,
            policy_unavailable: DegradationMode::FailClosed,
            token_broker_unavailable: DegradationMode::FailClosed,
            registry_unavailable: DegradationMode::FailClosed,
            nats_unavailable: NatsFailureMode::WriteWAL,
            session_unavailable: SessionFailureMode::SkipSessionAnalysis,
            audit_strict: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradationMode {
    /// 503 - block request (default for all stages).
    FailClosed,
    /// Proceed with risk=0.5 (Suspicious) and alert.
    AllowWithAlert,
    /// Use last-known-good from Redis cache.
    ApplyCachedRules,
    /// Use hardcoded deny list only.
    ApplyDefaultDeny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionFailureMode {
    SkipSessionAnalysis,
    FailClosed,
}

impl Default for SessionFailureMode {
    fn default() -> Self {
        SessionFailureMode::SkipSessionAnalysis
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatsFailureMode {
    /// Write to WAL for later replay (default).
    WriteWAL,
    /// Drop event with warning log.
    DropWithWarning,
    /// Block until NATS recovers.
    Backpressure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_degradation_config_default_intent_unavailable() {
        let cfg = DegradationConfig::default();
        assert_eq!(cfg.intent_unavailable, DegradationMode::FailClosed);
    }

    #[test]
    fn test_degradation_config_default_policy_unavailable() {
        let cfg = DegradationConfig::default();
        assert_eq!(cfg.policy_unavailable, DegradationMode::FailClosed);
    }

    #[test]
    fn test_degradation_config_default_token_broker_unavailable() {
        let cfg = DegradationConfig::default();
        assert_eq!(cfg.token_broker_unavailable, DegradationMode::FailClosed);
    }

    #[test]
    fn test_degradation_config_default_registry_unavailable() {
        let cfg = DegradationConfig::default();
        assert_eq!(cfg.registry_unavailable, DegradationMode::FailClosed);
    }

    #[test]
    fn test_degradation_config_default_nats_unavailable() {
        let cfg = DegradationConfig::default();
        assert_eq!(cfg.nats_unavailable, NatsFailureMode::WriteWAL);
    }

    #[test]
    fn test_degradation_config_default_audit_strict() {
        let cfg = DegradationConfig::default();
        assert!(!cfg.audit_strict);
    }

    #[test]
    fn test_degradation_mode_serde_roundtrip() {
        for mode in [
            DegradationMode::FailClosed,
            DegradationMode::AllowWithAlert,
            DegradationMode::ApplyCachedRules,
            DegradationMode::ApplyDefaultDeny,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: DegradationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn test_nats_failure_mode_serde_roundtrip() {
        for mode in [
            NatsFailureMode::WriteWAL,
            NatsFailureMode::DropWithWarning,
            NatsFailureMode::Backpressure,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: NatsFailureMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn test_degradation_config_full_serde_roundtrip() {
        let cfg = DegradationConfig {
            intent_unavailable: DegradationMode::AllowWithAlert,
            policy_unavailable: DegradationMode::ApplyCachedRules,
            token_broker_unavailable: DegradationMode::ApplyDefaultDeny,
            registry_unavailable: DegradationMode::FailClosed,
            nats_unavailable: NatsFailureMode::Backpressure,
            session_unavailable: SessionFailureMode::FailClosed,
            audit_strict: true,
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let back: DegradationConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(back.intent_unavailable, DegradationMode::AllowWithAlert);
        assert_eq!(back.policy_unavailable, DegradationMode::ApplyCachedRules);
        assert_eq!(
            back.token_broker_unavailable,
            DegradationMode::ApplyDefaultDeny
        );
        assert_eq!(back.registry_unavailable, DegradationMode::FailClosed);
        assert_eq!(back.nats_unavailable, NatsFailureMode::Backpressure);
        assert!(back.audit_strict);
    }
}
