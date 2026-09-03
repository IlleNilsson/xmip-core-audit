#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use xmip_core::{AuditId, ExecutionPhase, ExecutionScope, Severity};

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

#[derive(Debug)]
pub struct AuditError {
    pub message: String,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for AuditError {}

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
