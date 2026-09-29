//! [`ProgramAudit`]: how an Xmip program audits what it does (ADR-0062
//! clause 1) — a host that started and stopped, an act an operator took
//! through it, every failure and an unhandled one first.
//!
//! A Rust program holds one; a .NET program and PowerShell reach the same
//! one through the runtime's library (`xmip_operate.h` section 9). Every
//! record is kept by policy — a program's acts are few and every one
//! matters — in the file sink [`FileSink::stated`] finds, or the operating
//! system's log when there is none.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use xcore::{AuditId, Clock, ExecutionPhase, IdGenerator, Severity, SystemClock, UuidV7Generator};

use crate::audit_record::AuditRecord;
use crate::emit::{Audit, AuditOutcome};
use crate::file_sink::FileSink;
use crate::keeper;
use crate::origin::Origin;
use crate::redaction::without_credentials;
use crate::{AuditError, AuditSink, MinimumSeverityPolicy};

/// A program's own acts keep everything.
const EVERYTHING: MinimumSeverityPolicy = MinimumSeverityPolicy {
    minimum: Severity::Information,
};

/// One program's audit: who it is and where its records go.
#[derive(Clone, Debug)]
pub struct ProgramAudit {
    origin: Origin,
    /// Where the process declared it belongs, once; shared by every clone,
    /// the panic hook's among them, so a record made anywhere after the
    /// declaration carries it.
    location: Arc<OnceLock<String>>,
    sink: Option<FileSink>,
}

impl ProgramAudit {
    /// `program` in this process, auditing into `directory` when it is
    /// stated, else where [`FileSink::stated`] says.
    #[must_use]
    pub fn new(program: &str, directory: Option<&Path>) -> Self {
        Self {
            origin: Origin::here(program),
            location: Arc::new(OnceLock::new()),
            sink: FileSink::stated(directory),
        }
    }

    /// Say where the process belongs — the location it declares (ADR-0053
    /// clause 3), `xmip:///C1/node/R1` for a node — on every record this
    /// audit and each of its clones makes from now on, so a reader knows
    /// whose a record is without reading the program's name (ADR-0062,
    /// amendment 2026-09-29). A process declares once: the first location
    /// stands, and a blank one is none.
    pub fn locate(&self, location: &str) {
        let location = location.trim();
        if !location.is_empty() {
            let _ = self.location.set(location.to_string());
        }
    }

    /// The location every record carries, once the process declared one.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.location.get().map(String::as_str)
    }

    /// The file records go to, or `None` when they go to the operating
    /// system's log.
    #[must_use]
    pub fn file(&self) -> Option<PathBuf> {
        self.sink.as_ref().map(FileSink::path)
    }

    /// Record one act, after everything handed to the [`keeper`] before it:
    /// a program's records are kept in the order it made them. An address's
    /// user and password never reach the record, in the message or in a
    /// property ([`without_credentials`]).
    ///
    /// # Errors
    /// Neither the sink nor the operating system's log kept it.
    pub fn record(
        &self,
        action: &str,
        phase: ExecutionPhase,
        severity: Severity,
        message: Option<&str>,
        properties: BTreeMap<String, String>,
    ) -> Result<AuditOutcome, AuditError> {
        keeper::settle();
        let record = AuditRecord {
            audit_id: AuditId::new(UuidV7Generator.next_u128()),
            origin: Origin {
                location: self.location.get().cloned(),
                ..self.origin.clone()
            },
            scope: None,
            action: action.to_string(),
            phase,
            severity,
            timestamp_unix_nanos: SystemClock.unix_timestamp_nanos(),
            message: message.map(without_credentials),
            properties: properties
                .into_iter()
                .map(|(key, value)| (key, without_credentials(&value)))
                .collect(),
        };
        let sink = self.sink.as_ref().map(|sink| sink as &dyn AuditSink);

        Audit::new(&EVERYTHING, sink).emit(&record)
    }

    /// Record that the program failed: `action`, the Failure phase, Error.
    ///
    /// # Errors
    /// As [`Self::record`].
    pub fn failed(&self, action: &str, message: &str) -> Result<AuditOutcome, AuditError> {
        self.record(
            action,
            ExecutionPhase::Failure,
            Severity::Error,
            Some(message),
            BTreeMap::new(),
        )
    }

    /// Audit every panic in this process as an unhandled failure, then let
    /// the panic go on as it would have.
    pub fn watch_panics(&self) {
        let audit = self.clone();
        let previous = std::panic::take_hook();

        std::panic::set_hook(Box::new(move |panic| {
            // A panic inside the panic hook aborts; a record that could not
            // be kept is all this can lose, and the previous hook still
            // prints the panic.
            let _ = audit.failed("unhandled", &panic.to_string());
            previous(panic);
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn a_program_records_into_the_directory_it_was_told() {
        let directory =
            std::env::temp_dir().join(format!("xmip-program-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let audit = ProgramAudit::new("probe", Some(&directory));

        let outcome = audit
            .record(
                "start",
                ExecutionPhase::Begin,
                Severity::Information,
                Some("started"),
                BTreeMap::from([("url".to_string(), "http://127.0.0.1:5087".to_string())]),
            )
            .expect("recorded");

        assert_eq!(outcome, AuditOutcome::Persisted);
        let file = audit.file().expect("a file sink");
        let text = fs::read_to_string(file).expect("read");
        assert!(text.contains("program = \"probe\""), "{text}");
        assert!(!text.contains("location"), "none declared: {text}");
        assert!(
            text.contains("\"url\" = \"http://127.0.0.1:5087\""),
            "{text}"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_located_program_puts_its_location_on_every_record() {
        let directory =
            std::env::temp_dir().join(format!("xmip-program-located-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let audit = ProgramAudit::new("probe", Some(&directory));
        let earlier = audit.clone();
        audit.locate(" xmip:///C1/node/R1 ");
        audit.locate("xmip:///C2");

        assert_eq!(
            audit.location(),
            Some("xmip:///C1/node/R1"),
            "the first stands"
        );
        earlier
            .failed("publish", "could not")
            .expect("a clone made before carries it too");
        audit
            .record(
                "stop",
                ExecutionPhase::Finished,
                Severity::Information,
                None,
                BTreeMap::new(),
            )
            .expect("recorded");

        let text = fs::read_to_string(audit.file().expect("a file")).expect("read");
        assert_eq!(
            text.matches("location = \"xmip:///C1/node/R1\"").count(),
            2,
            "{text}"
        );
        let blank = ProgramAudit::new("probe", None);
        blank.locate("  ");
        assert_eq!(blank.location(), None);
        let _ = fs::remove_dir_all(&directory);
    }
}
