use crate::signing::{MicroTokenPayload, SigningKeyManager};
use uuid::Uuid;

/// Mint a scoped, short-lived micro-token.
pub fn mint_micro_token(
    key_manager: &SigningKeyManager,
    agent_id: &str,
    scopes: &[String],
    tool_binding: &str,
    ttl_secs: u32,
    request_id: Option<String>,
    session_id: Option<String>,
    trust_level: Option<String>,
) -> Result<(String, String, String), String> {
    let jti = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    let claims = MicroTokenPayload {
        sub: agent_id.to_string(),
        iss: "agentguard".to_string(),
        aud: "tool-service".to_string(),
        exp: now + ttl_secs as i64,
        scope: scopes.join(" "),
        jti: jti.clone(),
        tool_binding: tool_binding.to_string(),
        request_id,
        session_id,
        trust_level,
    };

    let token = key_manager.sign_token(&claims)?;
    let scope = claims.scope.clone();

    Ok((token, jti, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_km() -> SigningKeyManager {
        SigningKeyManager::generate()
    }

    #[test]
    fn test_mint_basic() {
        let km = make_km();
        let (token, jti, scope) = mint_micro_token(
            &km,
            "agent-1",
            &["db:read".to_string()],
            "bind-hash",
            30,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!token.is_empty());
        assert!(!jti.is_empty());
        assert_eq!(scope, "db:read");

        // Token should be verifiable
        let verified = km.verify_token(&token).unwrap();
        assert_eq!(verified.sub, "agent-1");
        assert_eq!(verified.tool_binding, "bind-hash");
    }

    #[test]
    fn test_mint_multiple_scopes() {
        let km = make_km();
        let (_, _, scope) = mint_micro_token(
            &km,
            "agent-1",
            &["db:read".to_string(), "db:write".to_string()],
            "bind",
            30,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(scope, "db:read db:write");
    }

    #[test]
    fn test_mint_empty_scopes() {
        let km = make_km();
        let (_, _, scope) = mint_micro_token(
            &km, "agent-1", &[], "bind", 30, None, None, None,
        )
        .unwrap();
        assert_eq!(scope, "");
    }

    #[test]
    fn test_mint_with_session_and_trust() {
        let km = make_km();
        let (token, _, _) = mint_micro_token(
            &km,
            "agent-1",
            &["db:read".to_string()],
            "bind",
            60,
            Some("req-001".to_string()),
            Some("sess-001".to_string()),
            Some("degraded".to_string()),
        )
        .unwrap();
        let verified = km.verify_token(&token).unwrap();
        assert_eq!(verified.request_id.as_deref(), Some("req-001"));
        assert_eq!(verified.session_id.as_deref(), Some("sess-001"));
        assert_eq!(verified.trust_level.as_deref(), Some("degraded"));
    }

    #[test]
    fn test_mint_jti_uniqueness() {
        let km = make_km();
        let mut jtis = std::collections::HashSet::new();
        for _ in 0..100 {
            let (_, jti, _) = mint_micro_token(
                &km, "agent-1", &[], "bind", 30, None, None, None,
            )
            .unwrap();
            jtis.insert(jti);
        }
        assert_eq!(jtis.len(), 100, "All JTIs should be unique");
    }

    #[test]
    fn test_mint_expiry_set_correctly() {
        let km = make_km();
        let before = chrono::Utc::now().timestamp();
        let (token, _, _) = mint_micro_token(
            &km, "agent-1", &[], "bind", 60, None, None, None,
        )
        .unwrap();
        let after = chrono::Utc::now().timestamp();
        let verified = km.verify_token(&token).unwrap();
        assert!(verified.exp >= before + 60);
        assert!(verified.exp <= after + 60);
    }

    #[test]
    fn test_mint_issuer_and_audience() {
        let km = make_km();
        let (token, _, _) = mint_micro_token(
            &km, "agent-1", &[], "bind", 30, None, None, None,
        )
        .unwrap();
        let verified = km.verify_token(&token).unwrap();
        assert_eq!(verified.iss, "agentguard");
        assert_eq!(verified.aud, "tool-service");
    }

    #[test]
    fn test_mint_tool_binding_preserved() {
        let km = make_km();
        let binding = "sha256:deadbeef1234567890";
        let (token, _, _) = mint_micro_token(
            &km, "agent-1", &[], binding, 30, None, None, None,
        )
        .unwrap();
        let verified = km.verify_token(&token).unwrap();
        assert_eq!(verified.tool_binding, binding);
    }
}
