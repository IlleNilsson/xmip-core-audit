//! A query answered a page at a time from the file, through its index
//! ([`crate::audit_index`]): the counts, groups and actions from what the
//! index counted of each kind, and the page from the few blocks it can be
//! in, read from the file as they are now (open problem 38). The page and
//! the counts are the ones [`crate::audit_scan`] gives over the same
//! records; the words and rules are [`AuditQuery`]'s.
//!
//! The page is found by counting. The records sort by their column, then
//! their time, then their identifier, so every kind whose column says the
//! same is one class, counted without reading a record. Within a class the
//! blocks are walked from the page's own end — the latest first where it
//! descends — counting, and the walk stops at the first block that ends
//! before the page can: once the blocks walked hold enough records at or
//! after some moment to fill the page, a block wholly before that moment
//! holds none of it. Of the blocks walked, only those that reach between
//! that moment and the latest one before which they hold no more than the
//! page skips are read.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::fs::File;
use std::path::Path;

use observe::run::shown;

use crate::AuditError;
use crate::audit_block::Block;
use crate::audit_column::Column;
use crate::audit_entry::AuditEntry;
use crate::audit_index::{Index, written};
use crate::audit_query::{AuditPage, AuditQuery};
use crate::audit_tally::Tally;

/// What a query decides of each kind.
struct Judged {
    /// Shown, who the query stands at and within its pattern and severity.
    standing: Vec<bool>,
    /// Of the action asked, where one is.
    acted: Vec<bool>,
}

/// A block walked: where it reaches in the page's order, which block, and
/// how many records of the class it holds.
#[derive(Clone, Copy)]
struct Walked {
    low: i128,
    high: i128,
    place: usize,
    count: usize,
}

impl Index {
    /// Ask the file the index is of; `None` where the index cannot answer:
    /// a verification, which walks every record, a page sorted by the
    /// summary, which no kind holds, and an index that holds nothing.
    ///
    /// # Errors
    /// The file could not be read, with the path and the reason.
    pub(crate) fn ask(
        &self,
        file: &Path,
        query: &AuditQuery,
    ) -> Result<Option<AuditPage>, AuditError> {
        if query.verify || query.sort == Column::Summary || !self.tallied {
            return Ok(None);
        }
        let refused = |error: std::io::Error| {
            AuditError::new(format!("{} could not be read: {error}", file.display()))
        };
        let mut opened = match File::open(file) {
            Ok(opened) => opened,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some(AuditPage::default()));
            }
            Err(error) => return Err(refused(error)),
        };
        let shown: Vec<bool> = self
            .kinds
            .iter()
            .map(|kind| shown(kind.hidden, query.including_hidden))
            .collect();
        let read = (0..self.kinds.len())
            .filter(|kind| shown[*kind])
            .map(|kind| self.totals[kind].records)
            .sum();

        if let Some(record) = &query.record {
            let found = self.find(&mut opened, record, &shown).map_err(refused)?;
            return Ok(Some(AuditPage {
                read,
                matched: found.len(),
                records: found,
                ..AuditPage::default()
            }));
        }

        let judged = Judged {
            standing: (0..self.kinds.len())
                .map(|kind| {
                    let made = &self.kinds[kind];
                    shown[kind] && query.who(made) && query.untimed(made)
                })
                .collect(),
            acted: self.kinds.iter().map(|kind| query.acted(kind)).collect(),
        };
        let mut tally = Tally::new(query);
        tally.read = read;
        let matched = self
            .count(&mut opened, query, &judged, &mut tally)
            .map_err(refused)?;
        let records = self
            .page(&mut opened, query, &judged, &matched)
            .map_err(refused)?;
        Ok(Some(tally.page(records)))
    }

    /// Count what stands where the query stands into `tally`, once per
    /// kind, and say how many of each kind matched: from the whole file's
    /// counts where the query names no time, else from each block's — by
    /// its counts where it is wholly within the time, by its records where
    /// it straddles it.
    fn count(
        &self,
        opened: &mut File,
        query: &AuditQuery,
        judged: &Judged,
        tally: &mut Tally<'_>,
    ) -> std::io::Result<Vec<usize>> {
        let kinds = self.kinds.len();
        let (mut standing, mut latest) = (vec![0_usize; kinds], vec![i128::MIN; kinds]);
        if query.from.is_none() && query.to.is_none() {
            for (kind, total) in self.totals.iter().enumerate() {
                if judged.standing[kind] {
                    (standing[kind], latest[kind]) = (total.records, total.latest);
                }
            }
        } else {
            for block in &self.blocks {
                if within(query, block) {
                    for count in &block.tally {
                        let kind = count.kind as usize;
                        if judged.standing[kind] {
                            standing[kind] += count.records as usize;
                            latest[kind] = latest[kind].max(count.latest);
                        }
                    }
                } else if reaches(query, block) {
                    self.each(opened, block, |entry| {
                        if let Some(kind) = self.kind_of(entry).map(|kind| kind as usize)
                            && judged.standing[kind]
                            && query.timed(entry.at_nanos)
                        {
                            standing[kind] += 1;
                            latest[kind] = latest[kind].max(entry.at_nanos);
                        }
                    })?;
                }
            }
        }
        for kind in 0..kinds {
            if standing[kind] > 0 {
                tally.stand(&self.kinds[kind], standing[kind], &written(latest[kind]));
            }
            if !judged.acted[kind] {
                standing[kind] = 0;
            }
        }
        Ok(standing)
    }

    /// The page: the classes in the page's order, each skipped by its count
    /// until the page starts, and read where it is.
    fn page(
        &self,
        opened: &mut File,
        query: &AuditQuery,
        judged: &Judged,
        matched: &[usize],
    ) -> std::io::Result<Vec<AuditEntry>> {
        let mut sorted: Vec<u32> = (0..self.kinds.len())
            .filter(|kind| matched[*kind] > 0)
            .filter_map(|kind| u32::try_from(kind).ok())
            .collect();
        sorted.sort_by(|left, right| self.by_column(query, *left, *right));
        let mut class_of = vec![usize::MAX; self.kinds.len()];
        let mut totals: Vec<usize> = Vec::new();
        for (place, kind) in sorted.iter().enumerate() {
            if place == 0 || self.by_column(query, sorted[place - 1], *kind) != Ordering::Equal {
                totals.push(0);
            }
            class_of[*kind as usize] = totals.len() - 1;
            if let Some(total) = totals.last_mut() {
                *total += matched[*kind as usize];
            }
        }

        let (mut skip, mut want) = (query.offset, query.limit);
        let mut records = Vec::new();
        let classes = totals.len();
        for step in 0..classes {
            let class = if query.descending {
                classes - 1 - step
            } else {
                step
            };
            if want == 0 {
                break;
            }
            if skip >= totals[class] {
                skip -= totals[class];
                continue;
            }
            let take = want.min(totals[class] - skip);
            let ours = |kind: u32| class_of[kind as usize] == class;
            records.extend(self.window(opened, query, judged, &ours, skip, take)?);
            want -= take;
            skip = 0;
        }
        Ok(records)
    }

    /// The records of one class from `skip` on, `take` of them, in the
    /// page's order, from the blocks they can be in alone.
    fn window(
        &self,
        opened: &mut File,
        query: &AuditQuery,
        judged: &Judged,
        ours: &dyn Fn(u32) -> bool,
        skip: usize,
        take: usize,
    ) -> std::io::Result<Vec<AuditEntry>> {
        // A moment in the page's order, greatest first either way.
        let first = |at: i128| if query.descending { at } else { !at };
        let walk: Box<dyn Iterator<Item = &u32>> = if query.descending {
            Box::new(self.by_latest.iter().rev())
        } else {
            Box::new(self.by_earliest.iter())
        };
        let most = skip + take;
        let mut walked: Vec<Walked> = Vec::new();
        // The blocks walked with the greatest starts that hold `most`
        // records, the least start among them on top: where the page ends,
        // at the latest.
        let mut ending: BinaryHeap<Reverse<(i128, usize)>> = BinaryHeap::new();
        let (mut held, mut before, mut high) = (0, 0, i128::MAX);
        let mut at_value: Option<(i128, usize)> = None;
        for place in walk.map(|place| *place as usize) {
            let block = &self.blocks[place];
            let (start, end) = (first(block.earliest), first(block.latest));
            let (low, block_high) = (start.min(end), start.max(end));
            if held >= most
                && ending
                    .peek()
                    .is_some_and(|Reverse((end, _))| block_high < *end)
            {
                break;
            }
            let count = self.count_in(opened, query, judged, ours, block)?;
            if count == 0 {
                continue;
            }
            // Where the page starts, at the earliest: the least end before
            // which the blocks hold no more than the page skips.
            if at_value.is_none_or(|(value, _)| value != block_high) {
                at_value = Some((block_high, before));
            }
            if at_value.is_some_and(|(_, above)| above <= skip) {
                high = block_high;
            }
            before += count;
            walked.push(Walked {
                low,
                high: block_high,
                place,
                count,
            });
            ending.push(Reverse((low, count)));
            held += count;
            while let Some(Reverse((_, least))) = ending.peek().copied()
                && held - least >= most
            {
                ending.pop();
                held -= least;
            }
        }
        let low = match ending.peek() {
            Some(Reverse((end, _))) if held >= most => *end,
            _ => i128::MIN,
        };

        let mut above = 0;
        let mut found: Vec<(usize, AuditEntry)> = Vec::new();
        walked.sort_by_key(|block| block.place);
        for block in walked {
            if block.high < low {
                continue;
            }
            if block.low > high {
                above += block.count;
                continue;
            }
            self.each(opened, &self.blocks[block.place], |entry| {
                let kind = self.kind_of(entry);
                if !(kind.is_some_and(ours) && query.standing(entry) && query.acted(entry)) {
                    return;
                }
                let at = first(entry.at_nanos);
                if at > high {
                    above += 1;
                } else if at >= low {
                    found.push((found.len(), entry.clone()));
                }
            })?;
        }
        found.sort_by(|(left_place, left), (right_place, right)| {
            query.order(left, right).then(left_place.cmp(right_place))
        });
        Ok(found
            .into_iter()
            .skip(skip.saturating_sub(above))
            .take(take)
            .map(|(_, entry)| entry)
            .collect())
    }

    /// How many records of the class one block holds where the query
    /// stands: by its counts where it is wholly within the query's time, by
    /// its records where it straddles it.
    fn count_in(
        &self,
        opened: &mut File,
        query: &AuditQuery,
        judged: &Judged,
        ours: &dyn Fn(u32) -> bool,
        block: &Block,
    ) -> std::io::Result<usize> {
        let matches =
            |kind: u32| ours(kind) && judged.standing[kind as usize] && judged.acted[kind as usize];
        if within(query, block) {
            return Ok(block
                .tally
                .iter()
                .filter(|count| matches(count.kind))
                .map(|count| count.records as usize)
                .sum());
        }
        let mut count = 0;
        if reaches(query, block) {
            self.each(opened, block, |entry| {
                if self.kind_of(entry).is_some_and(matches) && query.timed(entry.at_nanos) {
                    count += 1;
                }
            })?;
        }
        Ok(count)
    }

    fn by_column(&self, query: &AuditQuery, left: u32, right: u32) -> Ordering {
        query
            .sort
            .compare(&self.kinds[left as usize], &self.kinds[right as usize])
    }
}

/// Whether the block is wholly within the query's time.
fn within(query: &AuditQuery, block: &Block) -> bool {
    query.timed(block.earliest) && query.timed(block.latest)
}

/// Whether some of the block may be within the query's time.
fn reaches(query: &AuditQuery, block: &Block) -> bool {
    !(query.from.is_some_and(|from| block.latest < from)
        || query.to.is_some_and(|to| block.earliest > to))
}
