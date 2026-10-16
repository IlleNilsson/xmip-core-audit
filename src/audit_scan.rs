//! A query answered over records read through once, in the order the log
//! holds them (ADR-0062, amendment 2026-09-29): records in hand, or the file
//! read a piece at a time by [`crate::audit_store`] where nothing shorter
//! answers — a verification, which walks every writer's chain whole
//! (ADR-0070 clause 5), a page sorted by the summary, which no index holds,
//! and a history whose kinds outgrew the store's budget.
//!
//! What it holds is the page, never the history: the records a page could
//! still be made of — at most twice the offset and the limit, cut back to
//! them whenever they reach it — the counts, and where each writer's chain
//! stands.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::audit_chain::Walker;
use crate::audit_entry::AuditEntry;
use crate::audit_query::{AuditPage, AuditQuery};
use crate::audit_tally::Tally;

/// One query being answered a record at a time.
pub(crate) struct Scan<'query> {
    query: &'query AuditQuery,
    tally: Tally<'query>,
    /// The records the page may be made of, each with its place in the log.
    kept: Vec<(usize, AuditEntry)>,
    seen: usize,
    /// Each writer's chain as far as it is read, where the query verifies.
    walkers: HashMap<String, Walker>,
    /// The writers of what matched, in the order of their first record.
    writers: Vec<String>,
}

impl<'query> Scan<'query> {
    pub(crate) fn new(query: &'query AuditQuery) -> Self {
        Self {
            query,
            tally: Tally::new(query),
            kept: Vec::new(),
            seen: 0,
            walkers: HashMap::new(),
            writers: Vec::new(),
        }
    }

    /// Read the next record of the log. What a hidden run recorded is not
    /// there for a query that did not include it: not counted, not grouped,
    /// not found by its identifier — and walked in its writer's chain all
    /// the same, since one left out would read as deleted.
    pub(crate) fn offer(&mut self, entry: &AuditEntry) {
        let place = self.seen;
        self.seen += 1;
        if self.query.verify
            && let (Some(writer), Some(link)) = (entry.writer.as_deref(), entry.link())
        {
            self.walkers
                .entry(writer.to_string())
                .or_insert_with(|| Walker::new(writer))
                .step(link);
        }
        if !observe::run::shown(entry.hidden, self.query.including_hidden) {
            return;
        }
        self.tally.read += 1;

        if let Some(record) = &self.query.record {
            if self.kept.is_empty() && &entry.audit_id == record {
                self.kept.push((place, entry.clone()));
                self.wrote(entry);
            }
            return;
        }
        if self.query.standing(entry) && self.tally.stand(entry, 1, &entry.at) {
            self.wrote(entry);
            self.keep(place, entry);
        }
    }

    fn wrote(&mut self, entry: &AuditEntry) {
        if let Some(writer) = &entry.writer
            && !self.writers.contains(writer)
        {
            self.writers.push(writer.clone());
        }
    }

    /// Keep `entry` while it may be on the page: of everything matched so
    /// far, among the first offset and limit in the page's order.
    fn keep(&mut self, place: usize, entry: &AuditEntry) {
        let most = self.query.offset.saturating_add(self.query.limit);
        if most == 0 {
            return;
        }
        self.kept.push((place, entry.clone()));
        if self.kept.len() >= most.saturating_mul(2) {
            let query = self.query;
            self.kept
                .select_nth_unstable_by(most - 1, |left, right| ordered(query, left, right));
            self.kept.truncate(most);
        }
    }

    /// The page and its counts.
    pub(crate) fn page(self) -> AuditPage {
        let Self {
            query,
            tally,
            mut kept,
            mut walkers,
            writers,
            ..
        } = self;
        let chains = if query.verify {
            writers
                .iter()
                .map(|writer| {
                    walkers
                        .remove(writer)
                        .map_or_else(|| Walker::new(writer).verdict(), Walker::verdict)
                })
                .collect()
        } else {
            Vec::new()
        };

        if query.record.is_some() {
            let records: Vec<AuditEntry> = kept.into_iter().map(|(_, entry)| entry).collect();
            return AuditPage {
                read: tally.read,
                matched: records.len(),
                records,
                chains,
                ..AuditPage::default()
            };
        }

        kept.sort_by(|left, right| ordered(query, left, right));
        let records = kept
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .map(|(_, entry)| entry)
            .collect();
        AuditPage {
            chains,
            ..tally.page(records)
        }
    }
}

/// The page's order, ties that remain to the place in the log: the order a
/// stable sort of the log gives.
fn ordered(
    query: &AuditQuery,
    (left_place, left): &(usize, AuditEntry),
    (right_place, right): &(usize, AuditEntry),
) -> Ordering {
    query.order(left, right).then(left_place.cmp(right_place))
}

impl AuditQuery {
    /// Ask `entries`, in the order the log holds them. What a hidden run
    /// recorded is not there for a query that did not include it: not
    /// counted, not grouped, not found by its identifier.
    #[must_use]
    pub fn ask<Entry: Borrow<AuditEntry>>(
        &self,
        entries: impl IntoIterator<Item = Entry>,
    ) -> AuditPage {
        let mut scan = Scan::new(self);
        for entry in entries {
            scan.offer(entry.borrow());
        }
        scan.page()
    }
}
