//! The blocks of an audit file read lately, kept as their records, so a
//! view that asks for the same page on every change of a cluster parses it
//! once (open problem 38). What it keeps is bounded in bytes, as the sizes
//! of the records it holds; the block read least lately is let go first,
//! and a block longer than a quarter of the budget is never kept — it is
//! read a piece at a time each time instead.
//!
//! A block is known by where it starts and ends in the file, so the newest
//! block, which grows as records are appended, is read again once it has.

use std::collections::VecDeque;
use std::mem::size_of;
use std::sync::Arc;

use crate::audit_entry::AuditEntry;

/// One block kept: where it starts and ends, its records and their bytes.
type Kept = ((u64, u64), Arc<Vec<AuditEntry>>, usize);

/// The records of the blocks read lately.
pub(crate) struct BlockCache {
    kept: VecDeque<Kept>,
    held: usize,
    budget: usize,
}

impl BlockCache {
    pub(crate) const fn new(budget: usize) -> Self {
        Self {
            kept: VecDeque::new(),
            held: 0,
            budget,
        }
    }

    /// The bytes the cache holds.
    pub(crate) const fn held(&self) -> usize {
        self.held
    }

    /// Whether a block of `bytes` in the file may be kept.
    pub(crate) const fn keeps(&self, bytes: u64) -> bool {
        bytes <= (self.budget / 4) as u64
    }

    /// The records of the block from `start` to `end`, where kept: now the
    /// one read most lately.
    pub(crate) fn get(&mut self, start: u64, end: u64) -> Option<Arc<Vec<AuditEntry>>> {
        let place = self.kept.iter().position(|(at, ..)| *at == (start, end))?;
        let found = self.kept.remove(place)?;
        let records = Arc::clone(&found.1);
        self.kept.push_back(found);
        Some(records)
    }

    /// Keep the records of the block from `start` to `end`, letting go of
    /// the least lately read until they fit.
    pub(crate) fn put(&mut self, start: u64, end: u64, records: Arc<Vec<AuditEntry>>) {
        let bytes = records.iter().map(entry_held).sum::<usize>();
        if bytes > self.budget {
            return;
        }
        while self.held + bytes > self.budget {
            let Some((_, _, freed)) = self.kept.pop_front() else {
                break;
            };
            self.held -= freed;
        }
        self.held += bytes;
        self.kept.push_back(((start, end), records, bytes));
    }
}

/// The bytes one record read back holds, as the sizes of its parts.
fn entry_held(entry: &AuditEntry) -> usize {
    let map = |pairs: &std::collections::BTreeMap<String, String>| {
        pairs
            .iter()
            .map(|(key, value)| 2 * size_of::<String>() + key.len() + value.len())
            .sum::<usize>()
    };
    size_of::<AuditEntry>()
        + entry.audit_id.len()
        + entry.at.len()
        + entry.program.len()
        + entry.host.len()
        + entry.process.len()
        + entry.location.as_ref().map_or(0, String::len)
        + entry.action.len()
        + entry.phase.len()
        + entry.severity.len()
        + entry.message.as_ref().map_or(0, String::len)
        + entry.writer.as_ref().map_or(0, String::len)
        + map(&entry.scope)
        + map(&entry.properties)
}
