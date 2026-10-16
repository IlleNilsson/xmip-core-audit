//! A block of an audit file's index ([`crate::audit_index`]): a run of whole
//! records by its bytes in the file, its earliest and latest time, and how
//! many records of each kind it holds — what a query counts and walks by
//! without reading a record (open problem 38).

use std::mem::size_of;

/// The records a new block holds.
pub const BLOCK: u32 = 64;

/// The bytes a new block holds at most.
pub const BLOCK_BYTES: u64 = 256 * 1024;

/// How many records of one kind a block holds, and the latest moment one
/// of them was written.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Count {
    pub kind: u32,
    pub records: u32,
    pub latest: i128,
}

/// A run of whole records in the file.
#[derive(Clone, Debug)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
    pub records: u32,
    pub earliest: i128,
    pub latest: i128,
    pub tally: Vec<Count>,
}

impl Block {
    /// A block of one record of `kind`, from `start` to `end` in the file,
    /// written at `at`.
    pub(crate) fn first(kind: u32, start: u64, end: u64, at: i128) -> Self {
        Self {
            start,
            end,
            records: 1,
            earliest: at,
            latest: at,
            tally: vec![Count {
                kind,
                records: 1,
                latest: at,
            }],
        }
    }

    /// Count one more record of `kind` ending at `end`, written at `at`;
    /// the bytes the block holds more for it.
    pub(crate) fn add(&mut self, kind: u32, end: u64, at: i128) -> usize {
        self.end = end;
        self.records += 1;
        self.earliest = self.earliest.min(at);
        self.latest = self.latest.max(at);
        if tally(&mut self.tally, kind, 1, at) {
            size_of::<Count>()
        } else {
            0
        }
    }

    /// Take in the block after this one: one block of both.
    pub(crate) fn absorb(&mut self, after: &Self) {
        self.end = after.end;
        self.records = self.records.saturating_add(after.records);
        self.earliest = self.earliest.min(after.earliest);
        self.latest = self.latest.max(after.latest);
        for count in &after.tally {
            tally(&mut self.tally, count.kind, count.records, count.latest);
        }
        self.tally.shrink_to_fit();
    }

    /// The bytes the block holds in the index, its two places in the
    /// index's orders with it.
    pub(crate) const fn held(&self) -> usize {
        size_of::<Self>() + 2 * size_of::<u32>() + self.tally.len() * size_of::<Count>()
    }
}

/// Count `count` records of `kind`, the latest at `latest`, in `counts`;
/// whether a count was added for it.
fn tally(counts: &mut Vec<Count>, kind: u32, count: u32, latest: i128) -> bool {
    if let Some(held) = counts.iter_mut().find(|held| held.kind == kind) {
        held.records = held.records.saturating_add(count);
        held.latest = held.latest.max(latest);
        return false;
    }
    counts.push(Count {
        kind,
        records: count,
        latest,
    });
    true
}
