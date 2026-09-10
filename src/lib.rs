#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use xcore::{AuditId, ExecutionPhase, ExecutionScope, Severity};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub audit_id: AuditId,
    pub scope: ExecutionScope,
    pub action: String,
    pub phase: ExecutionPhase,
    pub severity: Severity,
    pub timestamp_unix_nanos: i128,
    pub message: Option<String>,
    pub properties: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditDecision {
    Record,
    Suppress,
}

pub trait AuditPolicy: Send + Sync {
    fn decide(
        &self,
        scope: &ExecutionScope,
        action: &str,
        phase: ExecutionPhase,
        severity: Severity,
    ) -> AuditDecision;
}

xcore::declare_error!(AuditError);

pub trait AuditSink: Send + Sync {
    fn write(&self, record: AuditRecord) -> Result<(), AuditError>;
}

pub struct Audit<'a> {
    policy: &'a dyn AuditPolicy,
    sink: &'a dyn AuditSink,
}

impl<'a> Audit<'a> {
    pub const fn new(policy: &'a dyn AuditPolicy, sink: &'a dyn AuditSink) -> Self {
        Self { policy, sink }
    }

    pub fn emit(&self, record: AuditRecord) -> Result<AuditDecision, AuditError> {
        let decision =
            self.policy
                .decide(&record.scope, &record.action, record.phase, record.severity);

        if decision == AuditDecision::Record {
            self.sink.write(record)?;
        }

        Ok(decision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimumSeverityPolicy {
    pub minimum: Severity,
}

impl AuditPolicy for MinimumSeverityPolicy {
    fn decide(
        &self,
        _: &ExecutionScope,
        _: &str,
        _: ExecutionPhase,
        severity: Severity,
    ) -> AuditDecision {
        let rank = |value| match value {
            Severity::Information => 0,
            Severity::Warning => 1,
            Severity::Error => 2,
        };

        if rank(severity) >= rank(self.minimum) {
            AuditDecision::Record
        } else {
            AuditDecision::Suppress
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use xcore::{ArtifactId, ArtifactRef, ExecutionId, JourneyId, MessageId};

    struct Kept(Mutex<Vec<AuditRecord>>);

    impl AuditSink for Kept {
        fn write(&self, record: AuditRecord) -> Result<(), AuditError> {
            self.0
                .lock()
                .map_err(|_| AuditError::new("poisoned"))?
                .push(record);
            Ok(())
        }
    }

    fn record(severity: Severity) -> AuditRecord {
        AuditRecord {
            audit_id: AuditId::new(1),
            scope: ExecutionScope {
                execution_id: ExecutionId::new(2),
                journey_id: JourneyId::new(3),
                message_id: MessageId::new(4),
                artifact: ArtifactRef {
                    artifact_id: ArtifactId::new(5),
                    artifact_type: "stream",
                    name: "probe".to_string(),
                    version: None,
                },
                node_id: None,
                cluster_id: None,
            },
            action: "receive".to_string(),
            phase: ExecutionPhase::Execute,
            severity,
            timestamp_unix_nanos: 0,
            message: None,
            properties: BTreeMap::new(),
        }
    }

    #[test]
    fn the_minimum_severity_policy_records_at_and_above_its_floor() {
        let policy = MinimumSeverityPolicy {
            minimum: Severity::Warning,
        };
        let sink = Kept(Mutex::new(Vec::new()));
        let audit = Audit::new(&policy, &sink);
        assert_eq!(
            audit.emit(record(Severity::Information)).expect("emitted"),
            AuditDecision::Suppress
        );
        assert_eq!(
            audit.emit(record(Severity::Warning)).expect("emitted"),
            AuditDecision::Record
        );
        assert_eq!(
            audit.emit(record(Severity::Error)).expect("emitted"),
            AuditDecision::Record
        );
        assert_eq!(
            sink.0.lock().expect("kept").len(),
            2,
            "only what was recorded reached the sink"
        );
    }

    #[test]
    fn an_audit_error_says_why() {
        assert_eq!(
            AuditError::new("the sink is full").to_string(),
            "the sink is full"
        );
    }
}
