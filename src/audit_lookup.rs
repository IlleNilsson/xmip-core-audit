//! One audit record found by its identifier through the file's index
//! ([`crate::audit_index`]): the query's `record` (ADR-0062, amendment
//! 2026-09-29), read from the blocks it can be in first. A version 7
//! identifier carries the moment it was minted, a moment before its record
//! was stamped, so the blocks written about then are read before the rest.

use std::fs::File;

use crate::audit_block::Block;
use crate::audit_entry::AuditEntry;
use crate::audit_index::Index;

/// How far from its identifier's moment a record's time is looked for
/// first.
const NEAR: i128 = 60 * 1_000_000_000;

impl Index {
    /// The first shown record with the identifier `record`: looked for
    /// first in the blocks written about when a version 7 identifier was
    /// minted, then in the rest, each in the order of the file. `shown`
    /// says of each kind whether the query reads it.
    ///
    /// # Errors
    /// A block could not be read, with the reason.
    pub(crate) fn find(
        &self,
        opened: &mut File,
        record: &str,
        shown: &[bool],
    ) -> std::io::Result<Vec<AuditEntry>> {
        let minted = minted(record);
        let near = |block: &Block| {
            minted.is_some_and(|at| block.earliest - NEAR <= at && at <= block.latest + NEAR)
        };
        let holds = |block: &Block| block.tally.iter().any(|count| shown[count.kind as usize]);
        let nearer = self.blocks.iter().filter(|block| near(block));
        let rest = self.blocks.iter().filter(|block| !near(block));
        let mut found = Vec::new();
        for block in nearer.chain(rest).filter(|block| holds(block)) {
            self.each(opened, block, |entry| {
                let seen = self.kind_of(entry).is_some_and(|kind| shown[kind as usize]);
                if found.is_empty() && seen && entry.audit_id == record {
                    found.push(entry.clone());
                }
            })?;
            if !found.is_empty() {
                break;
            }
        }
        Ok(found)
    }
}

/// The moment a version 7 identifier was minted, in nanoseconds since the
/// epoch: its first 48 bits are its milliseconds.
fn minted(record: &str) -> Option<i128> {
    let hex: String = record.chars().filter(|c| *c != '-').take(13).collect();
    if hex.len() < 13 || !hex.ends_with('7') {
        return None;
    }
    let milliseconds = i128::from_str_radix(&hex[..12], 16).ok()?;
    Some(milliseconds * 1_000_000)
}
