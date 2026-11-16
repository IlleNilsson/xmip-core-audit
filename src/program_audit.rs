//! [`ProgramAudit`]: how an Xmip program audits what it does (ADR-0062
//! clause 1) — a host that started and stopped, an act an operator took
//! through it, every failure and an unhandled one first.
//!
//! A Rust program holds one; a .NET program and PowerShell reach the same
//! one through the runtime's library (`xmip_operate.h` section 9). Every
//! record is kept by policy — a program's acts are few and every one
//! matters — by the sink the program that runs handed in as it started,
//! every Xmip program's being `xmip-core-audit-file`'s file sink, or by the
//! operating system's log it handed in ([`crate::operating_system_log`])
//! where there is none or the sink cannot keep a record. Which sink and
//! which log, audit does not know: it holds each by its seam.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use xcore::{AuditId, Clock, ExecutionPhase, IdGenerator, Severity, SystemClock, UuidV7Generator};

use crate::audit_record::AuditRecord;
use crate::emit::{Audit, AuditOutcome};
use crate::keeper;
use crate::origin::Origin;
use crate::redaction::without_credentials;
use crate::{AuditError, AuditSink, MinimumSeverityPolicy};

/// A program's own acts keep everything.
const EVERYTHING: MinimumSeverityPolicy = MinimumSeverityPolicy {
    minimum: Severity::Information,
};

/// One program's audit: who it is and where its records go.
#[derive(Clone)]
pub struct ProgramAudit {
    origin: Origin,
    /// Where the process declared it belongs, once; shared by every clone,
    /// the panic hook's among them, so a record made anywhere after the
    /// declaration carries it.
    location: Arc<OnceLock<String>>,
    /// Whether the process belongs to a run that declared itself hidden;
    /// shared by every clone as the location is.
    hidden: Arc<AtomicBool>,
    /// The sink the program handed in, shared by every clone.
    sink: Option<Arc<dyn AuditSink>>,
}

impl fmt::Debug for ProgramAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProgramAudit")
            .field("origin", &self.origin)
            .field("location", &self.location)
            .field("hidden", &self.hidden)
            .field("sink", &self.sink.is_some())
            .finish()
    }
}

impl ProgramAudit {
    /// `program` in this process, its records kept by `sink`, the one the
    /// program that runs hands in as it starts; with none, every record goes
    /// to the operating system's log.
    #[must_use]
    pub fn new(program: &str, sink: Option<impl AuditSink + 'static>) -> Self {
        Self {
            origin: Origin::here(program),
            location: Arc::new(OnceLock::new()),
            hidden: Arc::new(AtomicBool::new(false)),
            sink: sink.map(|sink| Arc::new(sink) as Arc<dyn AuditSink>),
        }
    }

    /// Say where the process belongs — the location it declares (ADR-0053
    /// clause 3), `xmip:///<cluster>/node/<node>` for a node — on every
    /// record this audit and each of its clones makes from now on, so a
    /// reader knows whose a record is without reading the program's name
    /// (ADR-0062, amendment 2026-09-29). A process declares once: the first location
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

    /// Say that the process belongs to a run that declared itself hidden —
    /// an assistant's test run (ADR-0028, amendment 2026-09-30) — on every
    /// record this audit and each of its clones makes from now on, so a
    /// reader leaves the records out with the run, by what the process
    /// declared and never by its name. A declaration is not taken back.
    pub fn hide(&self) {
        self.hidden.store(true, Ordering::Relaxed);
    }

    /// Whether every record from now on says the process is hidden.
    #[must_use]
    pub fn hidden(&self) -> bool {
        self.hidden.load(Ordering::Relaxed)
    }

    /// Where a record made now says it came from: the program, its host and
    /// process, the location it declared and whether it is hidden. A record
    /// this audit does not keep itself — one written to Xmip Storage, where
    /// a node's Publication is audited (ADR-0062, amendment 2026-10-01) —
    /// carries it, so a reader groups it with the program's own.
    #[must_use]
    pub fn origin(&self) -> Origin {
        Origin {
            location: self.location.get().cloned(),
            hidden: self.hidden(),
            ..self.origin.clone()
        }
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
            origin: self.origin(),
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
        Audit::new(&EVERYTHING, self.sink.as_deref()).emit(&record)
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
    use std::sync::Mutex;

    /// A sink that keeps what it is handed, for the test to read.
    #[derive(Clone, Default)]
    struct Kept(Arc<Mutex<Vec<AuditRecord>>>);

    impl AuditSink for Kept {
        fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0
                .lock()
                .map_err(|_| AuditError::new("poisoned"))?
                .push(record.clone());
            Ok(())
        }
    }

    impl Kept {
        /// Every record kept, as its TOML table.
        fn text(&self) -> String {
            self.0
                .lock()
                .expect("kept")
                .iter()
                .map(AuditRecord::toml)
                .collect()
        }
    }

    #[test]
    fn a_program_records_into_the_sink_it_was_handed() {
        let kept = Kept::default();
        let audit = ProgramAudit::new("probe", Some(kept.clone()));

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
        let text = kept.text();
        assert!(text.contains("program = \"probe\""), "{text}");
        assert!(!text.contains("location"), "none declared: {text}");
        assert!(
            text.contains("\"url\" = \"http://127.0.0.1:5087\""),
            "{text}"
        );
    }

    #[test]
    fn a_located_program_puts_its_location_on_every_record() {
        let kept = Kept::default();
        let audit = ProgramAudit::new("probe", Some(kept.clone()));
        let earlier = audit.clone();
        let cluster = configure::fixture::test_cluster();
        let at = cluster.node_scope(0);
        audit.locate(&format!(" {at} "));
        audit.locate(&format!("xmip:///{}", cluster.other()));

        assert_eq!(audit.location(), Some(at.as_str()), "the first stands");
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

        let text = kept.text();
        assert_eq!(
            text.matches(&format!("location = \"{at}\"")).count(),
            2,
            "{text}"
        );
        let blank = ProgramAudit::new("probe", None::<Kept>);
        blank.locate("  ");
        assert_eq!(blank.location(), None);
    }

    #[test]
    fn a_hidden_program_says_so_on_every_record_its_clones_make_too() {
        let kept = Kept::default();
        let audit = ProgramAudit::new("probe", Some(kept.clone()));
        let earlier = audit.clone();
        audit.failed("before", "not hidden yet").expect("recorded");
        audit.hide();

        assert!(earlier.hidden(), "a clone shares the declaration");
        earlier.failed("after", "hidden").expect("recorded");

        let text = kept.text();
        assert_eq!(text.matches("hidden = \"true\"").count(), 1, "{text}");
    }
}
