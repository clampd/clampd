use ag_common::errors::AgError;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Row returned from the agents table.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct AgentRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub declared_purpose: Option<String>,
    pub state: String,
    pub framework: Option<String>,
    pub auth_mode: Option<String>,
    pub credential_hash: Option<String>,
    pub idp_subject: Option<String>,
    pub killed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub kill_reason: Option<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub tool_descriptor_hash: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Row from agent_boundaries table.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub struct BoundaryRow {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub org_id: Uuid,
    pub max_calls_per_min: Option<i32>,
    pub max_calls_per_session: Option<i32>,
    pub max_records_per_query: Option<i32>,
    pub max_data_mb_per_hour: Option<f64>,
    pub active_hours_start: Option<String>,
    pub active_hours_end: Option<String>,
    pub blocked_domains: Option<Vec<String>>,
    pub allowed_domains: Option<Vec<String>>,
    // AP2 Payment guardrails
    pub max_payment_per_tx_cents: Option<i64>,
    pub max_payment_per_hour_cents: Option<i64>,
    pub approved_vendors: Option<Vec<String>>,
}

pub struct AgentRepository {
    pool: PgPool,
}

impl AgentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Count active agents for an organisation.
    pub async fn count_agents(&self, org_id: &str) -> Result<i64, AgError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM agents WHERE org_id = $1::uuid AND state != 'killed'"
        )
        .bind(org_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AgError::Internal(format!("count_agents: {}", e)))?;
        Ok(row.0)
    }

    /// Check if an agent with the same name already exists in the org.
    /// Includes ALL states (even killed) — prevents kill-then-spoof attack
    /// where attacker kills the real agent and registers a clone.
    pub async fn agent_name_exists(&self, org_id: &str, name: &str) -> Result<bool, AgError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM agents WHERE org_id = $1::uuid AND name = $2"
        )
        .bind(org_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AgError::Internal(format!("agent_name_exists: {}", e)))?;
        Ok(row.0 > 0)
    }

    /// Expose the pool for baseline queries (baselines module uses raw pool).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[instrument(skip(self))]
    pub async fn get_agent(&self, agent_id: Uuid) -> Result<AgentRow, AgError> {
        sqlx::query_as::<_, AgentRow>(
            "SELECT id, org_id, name, description, declared_purpose, state,
                    framework, auth_mode, credential_hash, idp_subject,
                    killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
             FROM agents WHERE id = $1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AgError::AgentNotFound(agent_id.to_string()))
    }

    #[instrument(skip(self))]
    pub async fn get_boundaries(&self, agent_id: Uuid) -> Result<Option<BoundaryRow>, AgError> {
        let row = sqlx::query_as::<_, BoundaryRow>(
            "SELECT id, agent_id, org_id, max_calls_per_min, max_calls_per_session,
                    max_records_per_query, max_data_mb_per_hour, active_hours_start,
                    active_hours_end, blocked_domains, allowed_domains,
                    max_payment_per_tx_cents, max_payment_per_hour_cents, approved_vendors
             FROM agent_boundaries WHERE agent_id = $1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    #[instrument(skip(self))]
    pub async fn update_state(
        &self,
        agent_id: Uuid,
        new_state: &str,
        kill_reason: Option<&str>,
    ) -> Result<AgentRow, AgError> {
        let row = if new_state == ag_common::models::AgentState::Killed.as_str() {
            sqlx::query_as::<_, AgentRow>(
                "UPDATE agents SET state = $2, killed_at = NOW(), kill_reason = $3,
                        credential_hash = NULL, updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, org_id, name, description, declared_purpose, state,
                           framework, auth_mode, credential_hash, idp_subject,
                           killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
            )
            .bind(agent_id)
            .bind(new_state)
            .bind(kill_reason)
            .fetch_optional(&self.pool)
            .await?
        } else if new_state == ag_common::models::AgentState::Active.as_str() {
            // Revive path: clear killed_at/kill_reason when returning to active
            sqlx::query_as::<_, AgentRow>(
                "UPDATE agents SET state = $2, killed_at = NULL, kill_reason = NULL,
                        updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, org_id, name, description, declared_purpose, state,
                           framework, auth_mode, credential_hash, idp_subject,
                           killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
            )
            .bind(agent_id)
            .bind(new_state)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AgentRow>(
                "UPDATE agents SET state = $2, updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, org_id, name, description, declared_purpose, state,
                           framework, auth_mode, credential_hash, idp_subject,
                           killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
            )
            .bind(agent_id)
            .bind(new_state)
            .fetch_optional(&self.pool)
            .await?
        };

        row.ok_or_else(|| AgError::AgentNotFound(agent_id.to_string()))
    }

    #[instrument(skip(self))]
    pub async fn update_risk_score(
        &self,
        agent_id: Uuid,
        risk_score: f64,
    ) -> Result<AgentRow, AgError> {
        // Persist the risk_score to the agents table along with updating last_active_at.
        // The agents table has a risk_score DOUBLE PRECISION column that was previously
        // ignored. If the column doesn't exist in the SELECT list (the dashboard schema
        // doesn't include it in the RETURNING set), we still update it and return the
        // standard agent row.
        sqlx::query_as::<_, AgentRow>(
            "UPDATE agents SET risk_score = $2, updated_at = NOW()
             WHERE id = $1
             RETURNING id, org_id, name, description, declared_purpose, state,
                       framework, auth_mode, credential_hash, idp_subject,
                       killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
        )
        .bind(agent_id)
        .bind(risk_score)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AgError::AgentNotFound(agent_id.to_string()))
    }

    /// Update agent state AND persist audit event in a single transaction.
    /// Ensures both succeed or both fail — no orphaned state changes without audit trail.
    #[instrument(skip(self))]
    pub async fn update_state_with_audit(
        &self,
        agent_id: Uuid,
        new_state: &str,
        kill_reason: Option<&str>,
        audit_action: &str,
        audit_details: &str,
        audit_actor: &str,
    ) -> Result<AgentRow, AgError> {
        let mut tx = self.pool.begin().await?;

        let row = if new_state == ag_common::models::AgentState::Killed.as_str() {
            sqlx::query_as::<_, AgentRow>(
                "UPDATE agents SET state = $2, killed_at = NOW(), kill_reason = $3,
                        credential_hash = NULL, updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, org_id, name, description, declared_purpose, state,
                           framework, auth_mode, credential_hash, idp_subject,
                           killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
            )
            .bind(agent_id)
            .bind(new_state)
            .bind(kill_reason)
            .fetch_optional(&mut *tx)
            .await?
        } else if new_state == ag_common::models::AgentState::Active.as_str() {
            sqlx::query_as::<_, AgentRow>(
                "UPDATE agents SET state = $2, killed_at = NULL, kill_reason = NULL,
                        updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, org_id, name, description, declared_purpose, state,
                           framework, auth_mode, credential_hash, idp_subject,
                           killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
            )
            .bind(agent_id)
            .bind(new_state)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_as::<_, AgentRow>(
                "UPDATE agents SET state = $2, updated_at = NOW()
                 WHERE id = $1
                 RETURNING id, org_id, name, description, declared_purpose, state,
                           framework, auth_mode, credential_hash, idp_subject,
                           killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
            )
            .bind(agent_id)
            .bind(new_state)
            .fetch_optional(&mut *tx)
            .await?
        };

        let row = row.ok_or_else(|| AgError::AgentNotFound(agent_id.to_string()))?;

        // Audit insert within the same transaction
        sqlx::query(
            "INSERT INTO agent_audit_log (id, agent_id, action, actor, details, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT DO NOTHING",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&agent_id.to_string())
        .bind(audit_action)
        .bind(audit_actor)
        .bind(audit_details)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(row)
    }

    /// List agents with optional state filter. Uses cursor-based pagination.
    #[instrument(skip(self))]
    pub async fn list_agents(
        &self,
        org_id: Option<Uuid>,
        state_filter: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<AgentRow>, AgError> {
        // Build query dynamically based on filters
        let mut query = String::from(
            "SELECT id, org_id, name, description, declared_purpose, state,
                    framework, auth_mode, credential_hash, idp_subject,
                    killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
             FROM agents WHERE 1=1",
        );
        let mut param_idx = 1u32;
        let mut binds: Vec<String> = Vec::new();

        if let Some(oid) = org_id {
            query.push_str(&format!(" AND org_id = ${}", param_idx));
            param_idx += 1;
            binds.push(oid.to_string());
        }

        if let Some(state) = state_filter {
            query.push_str(&format!(" AND state = ${}", param_idx));
            param_idx += 1;
            binds.push(state.to_string());
        }

        if let Some(c) = cursor {
            query.push_str(&format!(" AND id > ${}", param_idx));
            param_idx += 1;
            binds.push(c.to_string());
        }

        query.push_str(&format!(" ORDER BY id ASC LIMIT ${}", param_idx));
        binds.push(limit.to_string());

        // sqlx requires compile-time type checking for query_as bindings,
        // so dynamic query building with mixed types (Uuid, &str, i64) needs
        // separate static queries per combination. 8 cases for 3 optional filters.
        // This is verbose but type-safe. The dynamic builder above is retained
        // as documentation of the intended query structure.
        let rows = match (org_id, state_filter, cursor) {
            (Some(oid), Some(state), Some(c)) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE org_id = $1 AND state = $2 AND id > $3
                     ORDER BY id ASC LIMIT $4",
                )
                .bind(oid)
                .bind(state)
                .bind(c)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(oid), Some(state), None) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE org_id = $1 AND state = $2
                     ORDER BY id ASC LIMIT $3",
                )
                .bind(oid)
                .bind(state)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(oid), None, Some(c)) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE org_id = $1 AND id > $2
                     ORDER BY id ASC LIMIT $3",
                )
                .bind(oid)
                .bind(c)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(oid), None, None) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE org_id = $1
                     ORDER BY id ASC LIMIT $2",
                )
                .bind(oid)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(state), Some(c)) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE state = $1 AND id > $2
                     ORDER BY id ASC LIMIT $3",
                )
                .bind(state)
                .bind(c)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(state), None) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE state = $1
                     ORDER BY id ASC LIMIT $2",
                )
                .bind(state)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, None, Some(c)) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents WHERE id > $1
                     ORDER BY id ASC LIMIT $2",
                )
                .bind(c)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, None, None) => {
                sqlx::query_as::<_, AgentRow>(
                    "SELECT id, org_id, name, description, declared_purpose, state,
                            framework, auth_mode, credential_hash, idp_subject,
                            killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at
                     FROM agents
                     ORDER BY id ASC LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows)
    }

    /// Create a new agent record.
    #[instrument(skip(self))]
    pub async fn create_agent(
        &self,
        org_id: &str,
        name: &str,
        declared_purpose: &str,
        credential_hash: &str,
        framework: &str,
        auth_mode: &str,
    ) -> Result<AgentRow, AgError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let org_uuid: Uuid = org_id
            .parse()
            .map_err(|_| AgError::Internal("Invalid org_id UUID".to_string()))?;
        sqlx::query_as::<_, AgentRow>(
            "INSERT INTO agents (id, org_id, name, declared_purpose, credential_hash, state, framework, auth_mode, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $8)
             RETURNING id, org_id, name, description, declared_purpose, state,
                       framework, auth_mode, credential_hash, idp_subject,
                       killed_at, kill_reason, allowed_scopes, tool_descriptor_hash, created_at, updated_at",
        )
        .bind(id)
        .bind(org_uuid)
        .bind(name)
        .bind(declared_purpose)
        .bind(credential_hash)
        .bind(framework)
        .bind(auth_mode)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(AgError::from)
    }

    /// Update the tool descriptor hash for rug-pull detection.
    #[instrument(skip(self))]
    pub async fn update_tool_descriptor_hash(
        &self,
        agent_id: Uuid,
        hash: &str,
    ) -> Result<(), AgError> {
        sqlx::query(
            "UPDATE agents SET tool_descriptor_hash = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(agent_id)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Soft-delete an agent by setting state to 'killed' (decommissioned).
    #[instrument(skip(self))]
    pub async fn delete_agent(
        &self,
        agent_id: Uuid,
        reason: Option<&str>,
    ) -> Result<AgentRow, AgError> {
        self.update_state(agent_id, "killed", reason).await
    }
}
