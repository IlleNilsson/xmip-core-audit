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
use codec::toml::{quote, quote_into};
use xcore::audit_chain::{Digest, digest, written};
use xcore::{AuditId, ExecutionPhase, Severity};

use crate::execution_scope::ExecutionScope;
use crate::origin::Origin;

/// The key a chained record's own digest is written under: the one line
/// its canonical form leaves out.
pub const DIGEST_KEY: &str = "digest";

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
        self.table(None).0
    }

    /// The record as the file sink appends it, in `writer`'s audit chain
    /// at `position`, after the record whose digest is `previous`
    /// (ADR-0070 clause 5): its table with `writer`, `position` and
    /// `previous` after its identifier, and its own digest after them —
    /// the SHA-256 of the table as it is without that one line, its
    /// canonical form. The table, and the digest.
    #[must_use]
    pub fn chained(&self, writer: &str, position: u64, previous: &Digest) -> (String, Digest) {
        let (canonical, at) = self.table(Some((writer, position, previous)));
        let own = digest(canonical.as_bytes());
        let line = format!("{DIGEST_KEY} = {}\n", quote(&written(&own)));
        (
            format!("{}{line}{}", &canonical[..at], &canonical[at..]),
            own,
        )
    }

    /// The table, with the chain's fields where they are given, and where
    /// a digest line goes in it: after them.
    fn table(&self, chain: Option<(&str, u64, &Digest)>) -> (String, usize) {
        // Each value quoted where it is written, never made a string first.
        let mut out = String::with_capacity(512);
        out.push_str("[[record]]\n");
        let field = |out: &mut String, key: &str, value: &dyn std::fmt::Display| {
            out.push_str(key);
            out.push_str(" = ");
            quote_into(out, value);
            out.push('\n');
        };
        field(&mut out, "audit_id", &self.audit_id);
        if let Some((writer, position, previous)) = chain {
            field(&mut out, "writer", &writer);
            field(&mut out, "position", &position);
            field(&mut out, "previous", &written(previous));
        }
        let at = out.len();

        field(&mut out, "at", &rfc3339_nanos(self.timestamp_unix_nanos));
        field(&mut out, "program", &self.origin.program);
        field(&mut out, "host", &self.origin.host);
        field(&mut out, "process", &self.origin.process);
        if let Some(location) = &self.origin.location {
            field(&mut out, "location", location);
        }
        if self.origin.hidden {
            field(&mut out, "hidden", &"true");
        }
        field(&mut out, "action", &self.action);
        field(&mut out, "phase", &self.phase.word());
        field(&mut out, "severity", &self.severity.word());

        if let Some(message) = &self.message {
            field(&mut out, "message", message);
        }

        if let Some(scope) = &self.scope {
            out.push_str("[record.scope]\n");
            field(&mut out, "execution_id", &scope.execution_id);
            field(&mut out, "journey_id", &scope.journey_id);
            field(&mut out, "message_id", &scope.message_id);
            field(&mut out, "artifact_type", &scope.artifact.artifact_type);
            field(&mut out, "artifact", &scope.artifact.name);
        }

        if !self.properties.is_empty() {
            out.push_str("[record.properties]\n");
            for (key, value) in &self.properties {
                quote_into(&mut out, key);
                out.push_str(" = ");
                quote_into(&mut out, value);
                out.push('\n');
            }
        }

        out.push('\n');
        (out, at)
    }

    /// The record as one line of text: what happened first, then where it
    /// came from. Control characters become spaces, so a line stays a line.
    #[must_use]
    pub fn line(&self) -> String {
        let mut out = format!(
            "{} {} {}",
            self.action,
            self.phase.word(),
            self.severity.word()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_scope::ArtifactRef;
    use xcore::{ExecutionId, JourneyId, MessageId};

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
        assert!(text.contains("phase = \"Failure\"\n"), "{text}");
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
                artifact_type: "stream",
                name: "probe".to_string(),
                version: None,
            },
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
        let at = configure::fixture::test_cluster().node_scope(0);
        probe.origin.location = Some(at.clone());

        assert!(
            probe
                .toml()
                .contains(&format!("process = \"42\"\nlocation = \"{at}\"\n")),
            "{}",
            probe.toml()
        );
        assert!(probe.line().contains(&format!("on edge-01 at {at},")));
    }

    #[test]
    fn a_hidden_process_says_so_after_its_location_and_nothing_else_does() {
        let mut probe = record();
        assert!(!probe.toml().contains("hidden"), "none declared");
        let root = configure::fixture::test_cluster().scope();
        probe.origin.location = Some(root.clone());
        probe.origin.hidden = true;

        assert!(
            probe
                .toml()
                .contains(&format!("location = \"{root}\"\nhidden = \"true\"\n")),
            "{}",
            probe.toml()
        );
        assert!(
            probe.line().contains(&format!("at {root}, hidden,")),
            "{}",
            probe.line()
        );
    }

    /// The bytes of a chain written before its rule moved below the audit
    /// capability (2026-11-13), held: every chain already written still
    /// verifies.
    #[test]
    fn a_chain_digests_as_it_always_has() {
        let (_, first) = record().chained("edge-01", 1, &[0; 32]);
        let (second_table, second) = record().chained("edge-01", 2, &first);
        assert_eq!(written(&first), GOLDEN_FIRST);
        assert_eq!(written(&second), GOLDEN_SECOND);
        assert!(
            second_table.contains(&format!("previous = \"{GOLDEN_FIRST}\"\n")),
            "{second_table}"
        );
    }

    const GOLDEN_FIRST: &str = "e0fa75a0f94593312804b3bad7586b6048bc6efbafe37851453a92a08b9ea6ac";
    const GOLDEN_SECOND: &str = "1a2d0dae91e7bb910fdf0569cdab6d22595b0854ac3be707475816d19bebe512";

    #[test]
    fn the_line_is_one_line_that_says_what_and_where() {
        let line = record().line();

        assert!(!line.contains('\n'), "{line}");
        assert!(
            line.starts_with("unhandled Failure Error: a \"quoted\" line"),
            "{line}"
        );
        assert!(line.contains("exception type=Boom"), "{line}");
        assert!(line.contains("Xmip.Gui.Web pid 42 on edge-01"), "{line}");
    }
}
