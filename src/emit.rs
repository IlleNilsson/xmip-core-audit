//! [`Audit`]: policy, then the sink, then — when the sink cannot keep the
//! record or there is none — the operating system's log. The fallback rule
//! of ADR-0062 clause 3 is written here and nowhere else in the estate.

use crate::audit_record::AuditRecord;
use crate::operating_system_log::OperatingSystemLog;
use crate::{AuditDecision, AuditError, AuditPolicy, AuditSink};

/// What became of one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// Policy suppressed it. Never a failure.
    Suppressed,
    /// The sink persisted it.
    Persisted,
    /// The sink could not, for `reason`, and the operating system's log
    /// holds it: `log` says which.
    OperatingSystem { log: String, reason: String },
}

pub struct Audit<'a> {
    policy: &'a dyn AuditPolicy,
    sink: Option<&'a dyn AuditSink>,
}

impl<'a> Audit<'a> {
    /// Audit by `policy` into `sink`; with no sink every recorded record
    /// goes to the operating system's log.
    pub const fn new(policy: &'a dyn AuditPolicy, sink: Option<&'a dyn AuditSink>) -> Self {
        Self { policy, sink }
    }

    /// Decide, then persist.
    ///
    /// # Errors
    /// Neither the sink nor the operating system's log kept a record policy
    /// recorded; the error names both reasons.
    pub fn emit(&self, record: &AuditRecord) -> Result<AuditOutcome, AuditError> {
        self.emit_to(record, OperatingSystemLog::write)
    }

    /// [`Self::emit`], with the operating system's log given: the tests hand
    /// in one that keeps the entry, so no test writes to this machine's log.
    pub(crate) fn emit_to(
        &self,
        record: &AuditRecord,
        fallback: fn(&AuditRecord, &str) -> Result<String, AuditError>,
    ) -> Result<AuditOutcome, AuditError> {
        // Failures are always audited and failure records always persisted:
        // that is not policy (doc/audit-record.md).
        let decision = if record.is_failure() {
            AuditDecision::Record
        } else {
            self.policy.decide(
                record.scope.as_ref(),
                &record.action,
                record.phase,
                record.severity,
            )
        };

        if decision == AuditDecision::Suppress {
            return Ok(AuditOutcome::Suppressed);
        }

        let reason = match self.sink {
            None => "no audit sink is configured".to_string(),
            Some(sink) => match sink.write(record) {
                Ok(()) => return Ok(AuditOutcome::Persisted),
                Err(error) => format!("the audit sink refused it: {error}"),
            },
        };
        let why = format!("Xmip audit could not persist this record ({reason}).");

        match fallback(record, &why) {
            Ok(log) => Ok(AuditOutcome::OperatingSystem { log, reason }),
            Err(error) => Err(AuditError::new(format!(
                "{reason}, and the operating system's log refused it too: {error}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MinimumSeverityPolicy;
    use crate::origin::Origin;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use xcore::{AuditId, ExecutionPhase, Severity};

    struct Kept(Mutex<Vec<AuditRecord>>);

    impl AuditSink for Kept {
        fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0
                .lock()
                .map_err(|_| AuditError::new("poisoned"))?
                .push(record.clone());
            Ok(())
        }
    }

    /// The operating system's log, kept in the test instead: it says where,
    /// and whether the sentence opened with why. `Result`, because that is
    /// the fallback's shape.
    #[allow(clippy::unnecessary_wraps)]
    fn kept_here(record: &AuditRecord, why: &str) -> Result<String, AuditError> {
        assert!(
            why.starts_with("Xmip audit could not persist this record ("),
            "{why}"
        );
        assert!(!record.line().is_empty());
        Ok("this test".to_string())
    }

    struct Refusing;

    impl AuditSink for Refusing {
        fn write(&self, _: &AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::new("the disk is full"))
        }
    }

    fn record(phase: ExecutionPhase, severity: Severity) -> AuditRecord {
        AuditRecord {
            audit_id: AuditId::new(1),
            origin: Origin::here("xmip-core-audit tests"),
            scope: None,
            action: "probe".to_string(),
            phase,
            severity,
            timestamp_unix_nanos: 0,
            message: Some("written by the audit crate's own test".to_string()),
            properties: BTreeMap::new(),
        }
    }

    const WARNING_UP: MinimumSeverityPolicy = MinimumSeverityPolicy {
        minimum: Severity::Warning,
    };

    #[test]
    fn policy_decides_and_the_sink_keeps_what_it_records() {
        let sink = Kept(Mutex::new(Vec::new()));
        let audit = Audit::new(&WARNING_UP, Some(&sink));
        let emit = |severity| audit.emit(&record(ExecutionPhase::Execute, severity));

        assert_eq!(
            emit(Severity::Information).expect("emitted"),
            AuditOutcome::Suppressed
        );
        assert_eq!(
            emit(Severity::Warning).expect("emitted"),
            AuditOutcome::Persisted
        );
        assert_eq!(
            emit(Severity::Error).expect("emitted"),
            AuditOutcome::Persisted
        );
        assert_eq!(sink.0.lock().expect("kept").len(), 2);
    }

    #[test]
    fn a_failure_is_recorded_whatever_policy_says() {
        let floor = MinimumSeverityPolicy {
            minimum: Severity::Error,
        };
        let sink = Kept(Mutex::new(Vec::new()));
        let audit = Audit::new(&floor, Some(&sink));

        let outcome = audit
            .emit(&record(ExecutionPhase::Failure, Severity::Warning))
            .expect("emitted");

        assert_eq!(
            outcome,
            AuditOutcome::Persisted,
            "the Failure phase is not policy"
        );
    }

    #[test]
    fn a_refused_record_goes_to_the_operating_system_log_and_says_why() {
        let audit = Audit::new(&WARNING_UP, Some(&Refusing));

        match audit.emit_to(&record(ExecutionPhase::Failure, Severity::Error), kept_here) {
            Ok(AuditOutcome::OperatingSystem { log, reason }) => {
                assert!(reason.contains("the disk is full"), "{reason}");
                assert_eq!(log, "this test");
            }
            other => panic!("not the operating system's log: {other:?}"),
        }
    }

    #[test]
    fn with_no_sink_a_recorded_record_goes_to_the_operating_system_log() {
        let audit = Audit::new(&WARNING_UP, None);

        match audit.emit_to(
            &record(ExecutionPhase::Execute, Severity::Warning),
            kept_here,
        ) {
            Ok(AuditOutcome::OperatingSystem { reason, .. }) => {
                assert_eq!(reason, "no audit sink is configured");
            }
            other => panic!("not the operating system's log: {other:?}"),
        }
        assert_eq!(
            audit
                .emit_to(
                    &record(ExecutionPhase::Execute, Severity::Information),
                    kept_here
                )
                .expect("suppressed"),
            AuditOutcome::Suppressed,
            "what policy suppresses reaches no log at all"
        );
    }
}
