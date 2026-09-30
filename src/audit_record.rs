//! One audit record, and the two ways it is written: as a TOML table for a
//! file (on disk the estate is TOML), and as one line for a log that keeps
//! text — the operating system's.
//!
//! `doc/audit-record.md` is the model: the two lifecycle shapes, severity
//! independent of phase. A Message's action carries its [`ExecutionScope`];
//! a program's own act — a host that started, a cmdlet that failed — has
//! none, and its [`Origin`] says where it came from (ADR-0062).

use std::collections::BTreeMap;
use std::fmt::Write;

use codec::civil::rfc3339_nanos;
use codec::toml::quote;
use xcore::{AuditId, ExecutionPhase, Severity};

use crate::execution_scope::ExecutionScope;
use crate::origin::Origin;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub audit_id: AuditId,
    pub origin: Origin,
    /// The Message execution this action belongs to; `None` for a program's
    /// own act.
    pub scope: Option<ExecutionScope>,
    pub action: String,
    pub phase: ExecutionPhase,
    pub severity: Severity,
    pub timestamp_unix_nanos: i128,
    pub message: Option<String>,
    pub properties: BTreeMap<String, String>,
}

impl AuditRecord {
    /// A failure: the `Failure` phase, or an `Error` whatever the phase.
    /// Always audited and always persisted; that is not policy.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        self.phase == ExecutionPhase::Failure || self.severity == Severity::Error
    }

    /// The record as one `[[record]]` table, so a file of them is a TOML
    /// document that grows by appending.
    #[must_use]
    pub fn toml(&self) -> String {
        let mut out = String::from("[[record]]\n");
        let mut field = |key: &str, value: &str| {
            // Writing to a String cannot fail.
            let _ = writeln!(out, "{key} = {}", quote(value));
        };

        field("audit_id", &self.audit_id.to_string());
        field("at", &rfc3339_nanos(self.timestamp_unix_nanos));
        field("program", &self.origin.program);
        field("host", &self.origin.host);
        field("process", &self.origin.process.to_string());
        if let Some(location) = &self.origin.location {
            field("location", location);
        }
        if self.origin.hidden {
            field("hidden", "true");
        }
        field("action", &self.action);
        field("phase", phase_word(self.phase));
        field("severity", severity_word(self.severity));

        if let Some(message) = &self.message {
            field("message", message);
        }

        if let Some(scope) = &self.scope {
            out.push_str("[record.scope]\n");
            let mut scoped = |key: &str, value: &str| {
                let _ = writeln!(out, "{key} = {}", quote(value));
            };
            scoped("execution_id", &scope.execution_id.to_string());
            scoped("journey_id", &scope.journey_id.to_string());
            scoped("message_id", &scope.message_id.to_string());
            scoped("artifact_type", scope.artifact.artifact_type);
            scoped("artifact", &scope.artifact.name);
        }

        if !self.properties.is_empty() {
            out.push_str("[record.properties]\n");
            for (key, value) in &self.properties {
                let _ = writeln!(out, "{} = {}", quote(key), quote(value));
            }
        }

        out.push('\n');
        out
    }

    /// The record as one line of text: what happened first, then where it
    /// came from. Control characters become spaces, so a line stays a line.
    #[must_use]
    pub fn line(&self) -> String {
        let mut out = format!(
            "{} {} {}",
            self.action,
            phase_word(self.phase),
            severity_word(self.severity)
        );

        if let Some(message) = &self.message {
            let _ = write!(out, ": {message}");
        }

        for (key, value) in &self.properties {
            let _ = write!(out, "; {key}={value}");
        }

        let _ = write!(
            out,
            " ({} pid {} on {}",
            self.origin.program, self.origin.process, self.origin.host
        );
        if let Some(location) = &self.origin.location {
            let _ = write!(out, " at {location}");
        }
        if self.origin.hidden {
            out.push_str(", hidden");
        }
        let _ = write!(
            out,
            ", audit {}, {})",
            self.audit_id,
            rfc3339_nanos(self.timestamp_unix_nanos)
        );

        out.chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect()
    }
}

/// A phase as the record model writes it.
#[must_use]
pub const fn phase_word(phase: ExecutionPhase) -> &'static str {
    match phase {
        ExecutionPhase::Begin => "begin",
        ExecutionPhase::Execute => "execute",
        ExecutionPhase::Finished => "finished",
        ExecutionPhase::Failure => "failure",
    }
}

/// A severity as the record model writes it.
#[must_use]
pub const fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Information => "information",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_scope::ArtifactRef;
    use xcore::{ArtifactId, ExecutionId, JourneyId, MessageId};

    fn record() -> AuditRecord {
        AuditRecord {
            audit_id: AuditId::new(1),
            origin: Origin {
                program: "Xmip.Gui.Web".to_string(),
                host: "edge-01".to_string(),
                process: 42,
                location: None,
                hidden: false,
            },
            scope: None,
            action: "unhandled".to_string(),
            phase: ExecutionPhase::Failure,
            severity: Severity::Error,
            timestamp_unix_nanos: 1_790_000_000_123_456_789,
            message: Some("a \"quoted\"\nline".to_string()),
            properties: BTreeMap::from([("exception type".to_string(), "Boom".to_string())]),
        }
    }

    #[test]
    fn a_failure_is_the_failure_phase_or_an_error() {
        let mut probe = record();
        assert!(probe.is_failure());
        probe.phase = ExecutionPhase::Finished;
        assert!(probe.is_failure(), "an error at any phase is a failure");
        probe.severity = Severity::Warning;
        assert!(!probe.is_failure());
    }

    #[test]
    fn the_table_quotes_every_value_and_key_as_toml() {
        let text = record().toml();

        assert!(text.starts_with("[[record]]\n"), "{text}");
        assert!(text.contains("program = \"Xmip.Gui.Web\"\n"), "{text}");
        assert!(text.contains("phase = \"failure\"\n"), "{text}");
        assert!(
            text.contains("message = \"a \\\"quoted\\\"\\nline\"\n"),
            "{text}"
        );
        assert!(text.contains("[record.properties]\n\"exception type\" = \"Boom\"\n"));
        assert!(
            text.contains("at = \"2026-09-21T14:13:20.123456789Z\"\n"),
            "{text}"
        );
    }

    #[test]
    fn a_scope_is_written_when_there_is_one() {
        let mut probe = record();
        probe.scope = Some(ExecutionScope {
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
        });

        let text = probe.toml();

        assert!(text.contains("[record.scope]\n"), "{text}");
        assert!(text.contains("artifact = \"probe\"\n"), "{text}");
    }

    #[test]
    fn a_location_is_written_when_the_process_declared_one() {
        let mut probe = record();
        assert!(
            !probe.toml().contains("location"),
            "none declared, none written"
        );
        probe.origin.location = Some("xmip:///C1/node/R1".to_string());

        assert!(
            probe
                .toml()
                .contains("process = \"42\"\nlocation = \"xmip:///C1/node/R1\"\n"),
            "{}",
            probe.toml()
        );
        assert!(probe.line().contains("on edge-01 at xmip:///C1/node/R1,"));
    }

    #[test]
    fn a_hidden_process_says_so_after_its_location_and_nothing_else_does() {
        let mut probe = record();
        assert!(!probe.toml().contains("hidden"), "none declared");
        probe.origin.location = Some("xmip:///CT".to_string());
        probe.origin.hidden = true;

        assert!(
            probe
                .toml()
                .contains("location = \"xmip:///CT\"\nhidden = \"true\"\n"),
            "{}",
            probe.toml()
        );
        assert!(
            probe.line().contains("at xmip:///CT, hidden,"),
            "{}",
            probe.line()
        );
    }

    #[test]
    fn the_line_is_one_line_that_says_what_and_where() {
        let line = record().line();

        assert!(!line.contains('\n'), "{line}");
        assert!(
            line.starts_with("unhandled failure error: a \"quoted\" line"),
            "{line}"
        );
        assert!(line.contains("exception type=Boom"), "{line}");
        assert!(line.contains("Xmip.Gui.Web pid 42 on edge-01"), "{line}");
    }
}
