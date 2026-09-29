//! The columns a reader of the audit shows and sorts by, and the order of
//! each (ADR-0062, amendment 2026-09-29): a time by its moment, a phase in
//! lifecycle order, a severity least first, the rest as text.

use std::cmp::Ordering;

use crate::audit_entry::AuditEntry;

/// The severities, least first, as the record model writes them.
pub const SEVERITIES: [&str; 3] = ["information", "warning", "error"];

/// The phases, in lifecycle order, as the record model writes them.
pub const PHASES: [&str; 4] = ["begin", "execute", "finished", "failure"];

/// What a record can be sorted by: the columns a reader shows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Column {
    #[default]
    At,
    Location,
    Node,
    Program,
    Host,
    Action,
    Phase,
    Severity,
    Summary,
}

impl Column {
    /// Every column, in the order a reader shows them.
    pub const ALL: [Self; 9] = [
        Self::At,
        Self::Location,
        Self::Node,
        Self::Program,
        Self::Host,
        Self::Action,
        Self::Phase,
        Self::Severity,
        Self::Summary,
    ];

    /// The column's word, as a query names it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::At => "at",
            Self::Location => "location",
            Self::Node => "node",
            Self::Program => "program",
            Self::Host => "host",
            Self::Action => "action",
            Self::Phase => "phase",
            Self::Severity => "severity",
            Self::Summary => "summary",
        }
    }

    /// The column a word names, exactly.
    #[must_use]
    pub fn named(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|column| column.word() == word)
    }

    /// Every column's word, joined for a sentence.
    #[must_use]
    pub fn words() -> String {
        Self::ALL.map(Self::word).join(", ")
    }

    /// `left` against `right` by this column alone. A word the record model
    /// does not write sorts before every word it does.
    #[must_use]
    pub fn compare(self, left: &AuditEntry, right: &AuditEntry) -> Ordering {
        let rank = |words: &[&str], word: &str| words.iter().position(|each| *each == word);
        match self {
            Self::At => left.at_nanos.cmp(&right.at_nanos),
            Self::Location => left.location.cmp(&right.location),
            Self::Node => left.node().cmp(&right.node()),
            Self::Program => left.program.cmp(&right.program),
            Self::Host => left.host.cmp(&right.host),
            Self::Action => left.action.cmp(&right.action),
            Self::Phase => rank(&PHASES, &left.phase).cmp(&rank(&PHASES, &right.phase)),
            Self::Severity => {
                rank(&SEVERITIES, &left.severity).cmp(&rank(&SEVERITIES, &right.severity))
            }
            Self::Summary => left.summary().cmp(&right.summary()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_column_is_named_by_its_word_and_nothing_else() {
        for column in Column::ALL {
            assert_eq!(Column::named(column.word()), Some(column));
        }
        assert_eq!(Column::named("At"), None, "a word is exact");
        assert!(Column::words().starts_with("at, location, node"));
    }

    #[test]
    fn a_severity_sorts_least_first_and_a_phase_in_lifecycle_order() {
        let entry = |phase: &str, severity: &str| AuditEntry {
            phase: phase.to_string(),
            severity: severity.to_string(),
            ..AuditEntry::default()
        };
        let (begin, failure) = (entry("begin", "error"), entry("failure", "warning"));

        assert_eq!(Column::Phase.compare(&begin, &failure), Ordering::Less);
        assert_eq!(
            Column::Severity.compare(&begin, &failure),
            Ordering::Greater
        );
    }
}
