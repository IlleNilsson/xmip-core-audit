//! What the store keeps of an audit file in place of its records: an index
//! of blocks, each a run of whole records by its bytes in the file, its
//! earliest and latest time, and how many records of each kind it holds
//! (open problem 38: an audit query reads a page at a time from the file).
//!
//! A kind is everything a query asks a record by except its time and its
//! identifier — its location, host, program, action, phase, severity and
//! whether its run was hidden — so a query counts, groups and finds the
//! blocks its page is in from the index alone, and reads only those blocks.
//! The kinds of a log are few: its programs and their acts. Each kind's
//! records are counted over the whole file too, so a query that names no
//! time counts without walking the blocks, and the blocks are kept in the
//! order of their times, so a page walks from its own end and stops where
//! the page is found.
//!
//! What it holds is bounded in bytes, not records. When it outgrows its
//! budget the older half of its blocks are merged two by two, until it fits
//! again: the newest blocks, where a reader begins, stay short, and only a
//! page deep in an old history reads a long block. Where even one block's
//! kinds do not fit — or a record's time is not written as the file sink
//! writes it, which the index holds as a number — it holds nothing and
//! every query reads the file through ([`crate::audit_scan`]).

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::hash::{BuildHasher, RandomState};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;

use codec::civil::rfc3339_nanos;

use crate::AuditError;
use crate::audit_block::{BLOCK, BLOCK_BYTES, Block};
use crate::audit_cache::BlockCache;
use crate::audit_entry::{AuditEntry, parse, pieces};
use crate::audit_fragment::tables;

/// How long the file sink writes a time: RFC 3339 to the nanosecond, in
/// UTC, so its text sorts as its moment does.
const WRITTEN: usize = "2026-09-21T14:13:20.061200000Z".len();

/// One kind's records in the whole file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Total {
    pub records: usize,
    pub latest: i128,
}

/// The index of one file.
pub(crate) struct Index {
    /// How far the file is indexed: up to its last whole table.
    read: u64,
    /// One record of each kind, holding only what makes it the kind.
    pub kinds: Vec<AuditEntry>,
    pub totals: Vec<Total>,
    known: HashMap<u64, Vec<u32>>,
    hasher: RandomState,
    pub blocks: Vec<Block>,
    /// The blocks by their latest time, then by their place, latest last.
    pub by_latest: Vec<u32>,
    /// The blocks by their earliest time, then by their place, earliest first.
    pub by_earliest: Vec<u32>,
    /// The blocks before this place stand where they belong in both orders.
    settled: usize,
    budget: usize,
    held: usize,
    /// Whether the index holds the file; `false` once it could not.
    pub tallied: bool,
    /// The blocks read lately, as their records.
    cache: RefCell<BlockCache>,
}

impl Index {
    /// An index of nothing yet, holding at most `budget` bytes: half for
    /// itself, half for the blocks it read lately.
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            read: 0,
            kinds: Vec::new(),
            totals: Vec::new(),
            known: HashMap::new(),
            hasher: RandomState::new(),
            blocks: Vec::new(),
            by_latest: Vec::new(),
            by_earliest: Vec::new(),
            settled: 0,
            budget: budget / 2,
            held: 0,
            tallied: true,
            cache: RefCell::new(BlockCache::new(budget / 2)),
        }
    }

    /// The bytes the index holds, as the sizes of what it keeps, the
    /// blocks it read lately with them.
    pub(crate) fn held(&self) -> usize {
        self.held + self.cache.borrow().held()
    }

    /// Index what was appended to `file` since the last time. A file that
    /// is not there holds nothing, and one that got shorter was replaced
    /// and is indexed again from its start.
    ///
    /// # Errors
    /// The file is there and could not be read, with the path and the reason.
    pub(crate) fn refresh(&mut self, file: &Path) -> Result<(), AuditError> {
        let refused = |error: std::io::Error| {
            AuditError::new(format!("{} could not be read: {error}", file.display()))
        };
        let mut opened = match File::open(file) {
            Ok(opened) => opened,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                *self = Self::new(self.budget * 2);
                return Ok(());
            }
            Err(error) => return Err(refused(error)),
        };
        let length = opened.metadata().map_err(refused)?.len();
        if length < self.read {
            *self = Self::new(self.budget * 2);
        }
        if !self.tallied || length == self.read {
            return Ok(());
        }

        opened.seek(SeekFrom::Start(self.read)).map_err(refused)?;
        pieces(&mut opened, |bytes| self.take(bytes)).map_err(refused)?;
        self.order();
        Ok(())
    }

    /// Index whole tables, the first at [`Self::read`].
    fn take(&mut self, bytes: &[u8]) {
        for table in tables(bytes) {
            let start = self.read;
            self.read += table.len() as u64;
            for entry in parse(table).entries {
                if !self.tallied {
                    return;
                }
                self.add(&entry, start, self.read);
            }
        }
    }

    fn add(&mut self, entry: &AuditEntry, start: u64, end: u64) {
        if entry.at.len() != WRITTEN || entry.at != rfc3339_nanos(entry.at_nanos) {
            self.drop_all();
            return;
        }
        let kind = self.kind_or_new(entry);
        let total = &mut self.totals[kind as usize];
        total.records += 1;
        total.latest = total.latest.max(entry.at_nanos);
        let at = entry.at_nanos;
        match self.blocks.last_mut() {
            Some(last) if last.records < BLOCK && end - last.start <= BLOCK_BYTES => {
                self.held += last.add(kind, end, at);
            }
            _ => {
                let block = Block::first(kind, start, end, at);
                self.held += block.held();
                self.blocks.push(block);
            }
        }
        self.settled = self.settled.min(self.blocks.len() - 1);
        self.fit();
    }

    /// The kind of `entry`, where the index has met it.
    pub(crate) fn kind_of(&self, entry: &AuditEntry) -> Option<u32> {
        let hash = self.hash(entry);
        self.known
            .get(&hash)?
            .iter()
            .copied()
            .find(|kind| same_kind(&self.kinds[*kind as usize], entry))
    }

    fn kind_or_new(&mut self, entry: &AuditEntry) -> u32 {
        if let Some(kind) = self.kind_of(entry) {
            return kind;
        }
        let kind = u32::try_from(self.kinds.len()).unwrap_or(u32::MAX);
        let hash = self.hash(entry);
        let made = AuditEntry {
            location: entry.location.clone(),
            host: entry.host.clone(),
            program: entry.program.clone(),
            action: entry.action.clone(),
            phase: entry.phase.clone(),
            severity: entry.severity.clone(),
            hidden: entry.hidden,
            ..AuditEntry::default()
        };
        self.held += kind_held(&made);
        self.kinds.push(made);
        self.totals.push(Total {
            records: 0,
            latest: i128::MIN,
        });
        self.known.entry(hash).or_default().push(kind);
        kind
    }

    fn hash(&self, entry: &AuditEntry) -> u64 {
        self.hasher.hash_one((
            &entry.location,
            &entry.host,
            &entry.program,
            &entry.action,
            &entry.phase,
            &entry.severity,
            entry.hidden,
        ))
    }

    /// Merge the older half of the blocks two by two until the index fits
    /// its budget; where one block cannot fit, hold nothing.
    fn fit(&mut self) {
        if self.held <= self.budget {
            return;
        }
        while self.held > self.budget && self.blocks.len() > 1 {
            self.merge();
        }
        if self.held > self.budget {
            self.drop_all();
        }
    }

    fn drop_all(&mut self) {
        *self = Self::new(self.budget * 2);
        self.tallied = false;
    }

    fn merge(&mut self) {
        let older = (self.blocks.len() / 2).max(2);
        let mut blocks = std::mem::take(&mut self.blocks).into_iter();
        let mut merged: Vec<Block> = Vec::with_capacity(older.div_ceil(2));
        for (place, block) in blocks.by_ref().take(older).enumerate() {
            match merged.last_mut() {
                Some(last) if place % 2 == 1 => last.absorb(&block),
                _ => merged.push(block),
            }
        }
        merged.extend(blocks);
        self.blocks = merged;
        self.settled = 0;
        self.held = self.kinds.iter().map(kind_held).sum::<usize>()
            + self.blocks.iter().map(Block::held).sum::<usize>();
    }

    /// Put the blocks that are not yet settled in their places in the two
    /// orders.
    fn order(&mut self) {
        let (Ok(changed), Ok(count)) = (
            u32::try_from(self.settled),
            u32::try_from(self.blocks.len()),
        ) else {
            return;
        };
        self.settled = self.blocks.len();
        self.by_latest.retain(|place| *place < changed);
        self.by_earliest.retain(|place| *place < changed);
        self.by_latest.extend(changed..count);
        self.by_earliest.extend(changed..count);
        // Nearly in order already, which the sort finds in one pass.
        let blocks = &self.blocks;
        self.by_latest
            .sort_by_key(|at| (blocks[*at as usize].latest, *at));
        self.by_earliest
            .sort_by_key(|at| (blocks[*at as usize].earliest, *at));
    }

    /// Hand each record of `block` to `offer`, as the cache keeps it, else
    /// read from `opened` now — a piece at a time, and kept where it fits.
    ///
    /// # Errors
    /// The block could not be read, with the reason.
    pub(crate) fn each(
        &self,
        opened: &mut File,
        block: &Block,
        mut offer: impl FnMut(&AuditEntry),
    ) -> std::io::Result<()> {
        if let Some(records) = self.cache.borrow_mut().get(block.start, block.end) {
            records.iter().for_each(offer);
            return Ok(());
        }
        opened.seek(SeekFrom::Start(block.start))?;
        let mut reader = opened.by_ref().take(block.end - block.start);
        let keeps = self.cache.borrow().keeps(block.end - block.start);
        let mut kept = Vec::new();
        let mut hand = |entries: Vec<AuditEntry>| {
            for entry in entries {
                offer(&entry);
                if keeps {
                    kept.push(entry);
                }
            }
        };
        let rest = pieces(&mut reader, |bytes| hand(parse(bytes).entries))?;
        hand(parse(&rest).entries);
        if keeps {
            let records = Arc::new(kept);
            self.cache.borrow_mut().put(block.start, block.end, records);
        }
        Ok(())
    }
}

/// A moment as the file sink writes it, which every indexed record's time
/// is: what a group's latest record says.
pub(crate) fn written(at: i128) -> String {
    rfc3339_nanos(at)
}

fn same_kind(kind: &AuditEntry, entry: &AuditEntry) -> bool {
    kind.location == entry.location
        && kind.host == entry.host
        && kind.program == entry.program
        && kind.action == entry.action
        && kind.phase == entry.phase
        && kind.severity == entry.severity
        && kind.hidden == entry.hidden
}

fn kind_held(kind: &AuditEntry) -> usize {
    size_of::<AuditEntry>()
        + size_of::<Total>()
        + size_of::<(u64, Vec<u32>)>()
        + kind.location.as_ref().map_or(0, String::len)
        + kind.host.len()
        + kind.program.len()
        + kind.action.len()
        + kind.phase.len()
        + kind.severity.len()
}
