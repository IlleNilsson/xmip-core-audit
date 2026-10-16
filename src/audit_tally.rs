//! What a query counts besides its page (ADR-0062, amendment 2026-09-29):
//! how many records the store shows, how many matched, the groups one step
//! down the drill and the actions where the query stands. Counted once,
//! here, whether the records come one at a time ([`crate::audit_scan`]) or
//! as the store's index counted them, many of a kind at once
//! ([`crate::audit_page`]), so the two answer the same words the same way.

use std::collections::{BTreeMap, BTreeSet};

use xcore::Severity;

use crate::audit_entry::AuditEntry;
use crate::audit_query::{AuditGroup, AuditPage, AuditQuery};

/// A query's counts so far.
pub(crate) struct Tally<'query> {
    query: &'query AuditQuery,
    /// How many records the store shows the query.
    pub read: usize,
    pub matched: usize,
    groups: BTreeMap<(u8, String), AuditGroup>,
    actions: BTreeSet<String>,
}

impl<'query> Tally<'query> {
    pub(crate) const fn new(query: &'query AuditQuery) -> Self {
        Self {
            query,
            read: 0,
            matched: 0,
            groups: BTreeMap::new(),
            actions: BTreeSet::new(),
        }
    }

    /// `count` records like `entry` stand where the query stands
    /// ([`AuditQuery::standing`]), the latest of them written at `latest`:
    /// their action is one to choose from, and where it is the action asked
    /// they match and are grouped. Whether they matched.
    pub(crate) fn stand(&mut self, entry: &AuditEntry, count: usize, latest: &str) -> bool {
        if !self.actions.contains(&entry.action) {
            self.actions.insert(entry.action.clone());
        }
        if !self.query.acted(entry) {
            return false;
        }
        self.matched += count;
        if self.query.program.is_none() {
            self.group(entry, count, latest);
        }
        true
    }

    fn group(&mut self, entry: &AuditEntry, count: usize, latest: &str) {
        let (rank, kind, who) = self.query.group_of(entry);
        let group = self
            .groups
            .entry((rank, who.clone()))
            .or_insert(AuditGroup {
                kind,
                who,
                count: 0,
                warnings: 0,
                errors: 0,
                latest: String::new(),
                hidden: false,
            });
        group.count += count;
        group.hidden |= entry.hidden;
        if entry.severity == Severity::Warning.word() {
            group.warnings += count;
        }
        if entry.severity == Severity::Error.word() {
            group.errors += count;
        }
        if latest > group.latest.as_str() {
            latest.clone_into(&mut group.latest);
        }
    }

    /// The page the counts stand beside.
    pub(crate) fn page(self, records: Vec<AuditEntry>) -> AuditPage {
        AuditPage {
            read: self.read,
            matched: self.matched,
            records,
            groups: self.groups.into_values().collect(),
            actions: self.actions.into_iter().collect(),
            ..AuditPage::default()
        }
    }
}
