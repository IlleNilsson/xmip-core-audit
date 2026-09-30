//! An audit record read back: the one reader of the `[[record]]` tables
//! [`crate::audit_record::AuditRecord::toml`] writes (ADR-0062, amendment
//! 2026-09-29). What was written as words is read as words — a phase, a
//! severity, a process id — because a reader shows them and sorts by them,
//! and a word it does not know is still shown rather than dropped.
//!
//! The file is written a whole table at a time and every table ends with a
//! blank line, so [`parse`] reads up to the last blank line and says how far
//! it read: what follows it is a table still being appended, read next time.

use std::collections::BTreeMap;

use codec::civil::read_rfc3339;
use codec::toml::unquote_prefix;
use observe::Scope;

/// One record as the file holds it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditEntry {
    pub audit_id: String,
    /// When, as written: RFC 3339 to the nanosecond.
    pub at: String,
    /// When, in nanoseconds since the Unix epoch; 0 where `at` is not a time.
    pub at_nanos: i128,
    pub program: String,
    pub host: String,
    pub process: String,
    /// The scope the process declared it serves, when it serves one.
    pub location: Option<String>,
    /// The process declared its run hidden (ADR-0028, amendment
    /// 2026-09-30); a reader leaves the record out unless asked.
    pub hidden: bool,
    pub action: String,
    pub phase: String,
    pub severity: String,
    pub message: Option<String>,
    /// The Message execution the action belongs to (`[record.scope]`), key
    /// to text; empty for a program's own act.
    pub scope: BTreeMap<String, String>,
    pub properties: BTreeMap<String, String>,
}

impl AuditEntry {
    /// The node the record's process is on, by the one rule
    /// ([`Scope::node`]): `R1` for `xmip:///C1/node/R1`, none for a roll,
    /// a cluster or a program outside a cluster.
    #[must_use]
    pub fn node(&self) -> Option<&str> {
        self.location
            .as_deref()
            .and_then(|location| Scope::new(location).node())
    }

    /// The cluster the record's process belongs to: the first segment of its
    /// location, none where it declared none.
    #[must_use]
    pub fn cluster(&self) -> Option<&str> {
        self.location
            .as_deref()
            .and_then(|location| Scope::new(location).segments().next())
    }

    /// What the record says in one line: its message, else its properties
    /// as `key=value`, cut at [`SUMMARY`] characters.
    #[must_use]
    pub fn summary(&self) -> String {
        let said = self.message.clone().unwrap_or_else(|| {
            self.properties
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(" · ")
        });
        let line: String = said
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect();

        if line.chars().count() > SUMMARY {
            let cut: String = line.chars().take(SUMMARY - 1).collect();
            format!("{cut}…")
        } else {
            line
        }
    }
}

/// How many characters a summary keeps.
pub const SUMMARY: usize = 200;

/// Which table a key belongs to.
enum Table {
    Record,
    Scope,
    Properties,
    Other,
}

/// The records `text` holds up to its last blank line, and the byte length
/// of what was read: everything after it is left for the next read. A line
/// that is not a key and a basic string is passed over.
#[must_use]
pub fn parse(text: &str) -> (Vec<AuditEntry>, usize) {
    let read = text.rfind("\n\n").map_or(0, |at| at + 2);
    let mut entries = Vec::new();
    let mut entry: Option<AuditEntry> = None;
    let mut table = Table::Other;

    for line in text[..read].lines().map(str::trim) {
        match line {
            "" => {}
            "[[record]]" => {
                entries.extend(entry.take());
                entry = Some(AuditEntry::default());
                table = Table::Record;
            }
            "[record.scope]" => table = Table::Scope,
            "[record.properties]" => table = Table::Properties,
            _ if line.starts_with('[') => table = Table::Other,
            _ => {
                if let (Some(entry), Some((key, value))) = (entry.as_mut(), pair(line)) {
                    keep(entry, &table, key, value);
                }
            }
        }
    }

    entries.extend(entry);
    (entries, read)
}

/// One `key = "value"` line: a bare key or a quoted one, then a basic
/// string and nothing after it.
fn pair(line: &str) -> Option<(String, String)> {
    let (key, rest) = if line.starts_with('"') {
        let (key, rest) = unquote_prefix(line).ok()?;
        (key, rest.trim_start())
    } else {
        let (key, rest) = line.split_once('=')?;
        (key.trim().to_string(), rest)
    };
    let rest = rest
        .trim_start()
        .strip_prefix('=')
        .unwrap_or(rest)
        .trim_start();
    let (value, after) = unquote_prefix(rest).ok()?;

    after.trim().is_empty().then_some((key, value))
}

fn keep(entry: &mut AuditEntry, table: &Table, key: String, value: String) {
    match table {
        Table::Scope => {
            entry.scope.insert(key, value);
        }
        Table::Properties => {
            entry.properties.insert(key, value);
        }
        Table::Other => {}
        Table::Record => match key.as_str() {
            "audit_id" => entry.audit_id = value,
            "at" => {
                entry.at_nanos = read_rfc3339(&value).unwrap_or(0);
                entry.at = value;
            }
            "program" => entry.program = value,
            "host" => entry.host = value,
            "process" => entry.process = value,
            "location" => entry.location = Some(value),
            "hidden" => entry.hidden = value == "true",
            "action" => entry.action = value,
            "phase" => entry.phase = value,
            "severity" => entry.severity = value,
            "message" => entry.message = Some(value),
            _ => {
                entry.properties.insert(key, value);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_record::AuditRecord;
    use crate::origin::Origin;
    use xcore::{AuditId, ExecutionPhase, Severity};

    fn written(action: &str, location: Option<&str>) -> String {
        AuditRecord {
            audit_id: AuditId::new(9),
            origin: Origin {
                program: "xmip-playground-C1-node-R1".to_string(),
                host: "edge-01".to_string(),
                process: 7,
                location: location.map(str::to_string),
                hidden: action == "hidden",
            },
            scope: None,
            action: action.to_string(),
            phase: ExecutionPhase::Failure,
            severity: Severity::Error,
            timestamp_unix_nanos: 1_790_000_000_123_456_789,
            message: Some("a \"quoted\"\nline".to_string()),
            properties: BTreeMap::from([("exception type".to_string(), "Boom".to_string())]),
        }
        .toml()
    }

    #[test]
    fn what_the_writer_writes_the_reader_reads_whole() {
        let text = written("start", Some("xmip:///C1/node/R1"));
        let (entries, read) = parse(&text);

        assert_eq!(read, text.len());
        let entry = &entries[0];
        assert_eq!(entry.program, "xmip-playground-C1-node-R1");
        assert_eq!(entry.location.as_deref(), Some("xmip:///C1/node/R1"));
        assert_eq!(entry.node(), Some("R1"));
        assert_eq!(entry.cluster(), Some("C1"));
        assert_eq!(entry.phase, "failure");
        assert_eq!(entry.severity, "error");
        assert_eq!(entry.at_nanos, 1_790_000_000_123_456_789);
        assert_eq!(entry.message.as_deref(), Some("a \"quoted\"\nline"));
        assert_eq!(entry.properties["exception type"], "Boom");
        assert_eq!(entry.summary(), "a \"quoted\" line");
    }

    #[test]
    fn a_hidden_process_is_read_back_hidden_and_the_rest_shown() {
        let (entries, _) = parse(&(written("hidden", None) + &written("start", None)));

        assert!(entries[0].hidden, "declared hidden");
        assert!(!entries[1].hidden, "declared nothing");
        assert!(!entries[0].properties.contains_key("hidden"));
    }

    #[test]
    fn a_table_still_being_appended_is_left_for_the_next_read() {
        let whole = written("start", None);
        let torn = format!("{whole}{}", &written("stop", None)[..40]);
        let (entries, read) = parse(&torn);

        assert_eq!(entries.len(), 1);
        assert_eq!(read, whole.len());
        assert_eq!(entries[0].node(), None, "no location, no node");
    }

    #[test]
    fn a_program_outside_a_cluster_has_no_node_and_no_cluster() {
        let (entries, _) = parse(&written("probe", None));

        assert_eq!(entries[0].cluster(), None);
        assert_eq!(entries[0].location, None);
    }

    #[test]
    fn a_summary_without_a_message_is_the_properties_cut_short() {
        let entry = AuditEntry {
            properties: BTreeMap::from([
                ("a".to_string(), "x".repeat(300)),
                ("b".to_string(), "y".to_string()),
            ]),
            ..AuditEntry::default()
        };

        let summary = entry.summary();
        assert_eq!(summary.chars().count(), SUMMARY);
        assert!(
            summary.starts_with("a=xxx") && summary.ends_with('…'),
            "{summary}"
        );
    }

    #[test]
    fn a_line_that_is_no_pair_is_passed_over() {
        let text = "[[record]]\naction = \"start\"\nnonsense\nphase = 1\n\n";
        let (entries, _) = parse(text);

        assert_eq!(entries[0].action, "start");
        assert_eq!(entries[0].phase, "");
    }
}
