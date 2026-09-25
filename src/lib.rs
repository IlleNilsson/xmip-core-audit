//! The audit record: the persistent accountability record of what Xmip did,
//! where, by whom, why, when and with what outcome — for every action a node
//! takes and for every Xmip program (ADR-0062).
//!
//! An [`audit_record::AuditRecord`] carries its origin, its scope when it
//! has one, its action, phase and severity; an [`AuditPolicy`] decides
//! record or suppress; an [`AuditSink`] persists; [`emit::Audit`] is the
//! one place that puts the three together, and the one place that sends a
//! record the sink could not keep to the operating system's log
//! ([`operating_system_log::OperatingSystemLog`]). Failures are always
//! audited and failure records are always persisted; that is not policy.
//!
//! A program audits through [`program_audit::ProgramAudit`], whose default
//! sink is [`file_sink::FileSink`]: the directory it is told, else
//! `XMIP_AUDIT_DIRECTORY`, else none and the operating system's log.

pub mod audit_record;
pub mod emit;
pub mod file_sink;
pub mod operating_system_log;
pub mod origin;
pub mod program_audit;
pub mod redaction;

#[cfg(unix)]
mod syslog;
#[cfg(windows)]
mod windows_event_log;

use audit_record::AuditRecord;
use xcore::{ExecutionPhase, ExecutionScope, Severity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditDecision {
    Record,
    Suppress,
}

/// What effective policy decides for one record. A record with no scope — a
/// program's own act, not a Message's — is asked about with `None`.
pub trait AuditPolicy: Send + Sync {
    fn decide(
        &self,
        scope: Option<&ExecutionScope>,
        action: &str,
        phase: ExecutionPhase,
        severity: Severity,
    ) -> AuditDecision;
}

xcore::declare_error!(AuditError);

/// Where a record is persisted. A sink that cannot keep a record says why;
/// [`emit::Audit`] then hands it to the operating system's log.
pub trait AuditSink: Send + Sync {
    /// Persist `record`.
    ///
    /// # Errors
    /// The record was not persisted, with the reason in words.
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimumSeverityPolicy {
    pub minimum: Severity,
}

impl AuditPolicy for MinimumSeverityPolicy {
    fn decide(
        &self,
        _: Option<&ExecutionScope>,
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

    #[test]
    fn the_minimum_severity_policy_decides_by_its_floor() {
        let policy = MinimumSeverityPolicy {
            minimum: Severity::Warning,
        };
        let decide = |severity| policy.decide(None, "receive", ExecutionPhase::Execute, severity);

        assert_eq!(decide(Severity::Information), AuditDecision::Suppress);
        assert_eq!(decide(Severity::Warning), AuditDecision::Record);
        assert_eq!(decide(Severity::Error), AuditDecision::Record);
    }

    #[test]
    fn an_audit_error_says_why() {
        assert_eq!(
            AuditError::new("the sink is full").to_string(),
            "the sink is full"
        );
    }
}
