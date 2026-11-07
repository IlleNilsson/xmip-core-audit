//! The audit store read: the file [`crate::file_sink::FileSink`] appends to,
//! asked by an [`AuditQuery`] (ADR-0062, amendment 2026-09-29).
//!
//! The store keeps no record. It keeps an index of each file it is asked
//! ([`crate::audit_index`]), shared by every caller in the process, and
//! extends it with what was appended since the last time: the file only
//! grows, so a view that asks again on every change of a cluster indexes a
//! few hundred bytes. A file that got shorter was replaced, and is indexed
//! again from its start. A page is read from the file through the index, a
//! few blocks of records at a time ([`crate::audit_page`]).
//!
//! What the indexes hold together is bounded in bytes by [`BUDGET`]: the
//! one asked least lately is let go first, and one alone that outgrows it
//! is coarsened, so a long history costs time to index once and never
//! memory beyond the budget (open problem 38). A query no index answers —
//! a verification, a page sorted by the summary, a history whose kinds
//! outgrew the budget — reads the file through, a piece at a time
//! ([`crate::audit_scan`]), holding its page and never the history.

use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use xcore::lock::Locked;

use crate::AuditError;
use crate::audit_entry::{AuditEntry, parse, pieces};
use crate::audit_fragment::Fragment;
use crate::audit_index::Index;
use crate::audit_query::{AuditPage, AuditQuery};
use crate::audit_scan::Scan;
use crate::file_sink::FileSink;

/// The bytes the indexes of one process hold together, at most, the blocks
/// each read lately with them — half the index, half those blocks. A
/// reader's process is a surface — the web or desktop monitor, the command
/// line, PowerShell — which reads no node's configuration and so no
/// `[tuning]`: this is the one value.
pub const BUDGET: usize = 16 << 20;

/// One file's index, and when it was asked last.
struct Kept {
    file: PathBuf,
    index: Index,
    asked: u64,
}

#[derive(Default)]
struct Indexes {
    kept: Vec<Kept>,
    asked: u64,
}

fn indexes() -> &'static Mutex<Indexes> {
    static INDEXES: LazyLock<Mutex<Indexes>> = LazyLock::new(|| Mutex::new(Indexes::default()));
    &INDEXES
}

/// The file a reader reads: the one a program writing into `directory`
/// would write, by the one rule ([`FileSink::stated`]) — `directory` when it
/// is given and not blank, else `XMIP_AUDIT_DIRECTORY`, else none.
#[must_use]
pub fn stated(directory: Option<&Path>) -> Option<PathBuf> {
    FileSink::stated(directory).map(|sink| sink.path())
}

/// Ask `file`. A file that is not there holds nothing: nothing has been
/// audited there yet. A verification reads the file's bytes as they are
/// now, past what the index holds, since a record changed in place leaves
/// the file as long as it was (ADR-0070 clause 5), and says its fragments.
///
/// # Errors
/// The file is there and could not be read, with the path and the reason.
pub fn ask(file: &Path, query: &AuditQuery) -> Result<AuditPage, AuditError> {
    let mut all = indexes()
        .lock()
        .map_err(|_| AuditError::new("the audit reader's index was poisoned"))?;
    let page = all.indexed(file, query, BUDGET)?;
    drop(all);
    match page {
        Some(page) => Ok(page),
        None => scan(file, query),
    }
}

/// The bytes the process's indexes hold now.
///
/// # Panics
/// Never: a poisoned lock is read through.
#[must_use]
pub fn held() -> usize {
    let all = indexes().locked();
    all.kept.iter().map(|kept| kept.index.held()).sum()
}

impl Indexes {
    /// The page from `file`'s index, kept within `budget` with the rest;
    /// `None` where it holds too little to answer.
    fn indexed(
        &mut self,
        file: &Path,
        query: &AuditQuery,
        budget: usize,
    ) -> Result<Option<AuditPage>, AuditError> {
        self.asked += 1;
        let place = self
            .kept
            .iter()
            .position(|kept| kept.file == file)
            .unwrap_or_else(|| {
                self.kept.push(Kept {
                    file: file.to_path_buf(),
                    index: Index::new(budget),
                    asked: 0,
                });
                self.kept.len() - 1
            });
        self.kept[place].asked = self.asked;
        self.kept[place].index.refresh(file)?;

        while self.kept.len() > 1
            && self
                .kept
                .iter()
                .map(|kept| kept.index.held())
                .sum::<usize>()
                > budget
        {
            let least = self
                .kept
                .iter()
                .enumerate()
                .min_by_key(|(_, kept)| kept.asked)
                .map_or(0, |(least, _)| least);
            self.kept.remove(least);
        }

        let Some(kept) = self.kept.iter().find(|kept| kept.file == file) else {
            return Ok(None);
        };
        kept.index.ask(file, query)
    }
}

/// Ask `file` by reading it through once, a piece at a time.
fn scan(file: &Path, query: &AuditQuery) -> Result<AuditPage, AuditError> {
    let mut scan = Scan::new(query);
    let fragments = each(file, |entry| scan.offer(entry))?;
    let page = scan.page();
    Ok(AuditPage {
        fragments: if query.verify { fragments } else { Vec::new() },
        ..page
    })
}

/// Hand every record `file` holds to `offer`, in the order written, and say
/// the bytes that are no whole record, each from its byte in the file — as
/// [`parse`] says them of the whole file, read a piece at a time.
///
/// # Errors
/// The file is there and could not be read, with the path and the reason.
pub fn each(file: &Path, mut offer: impl FnMut(&AuditEntry)) -> Result<Vec<Fragment>, AuditError> {
    let refused = |error: std::io::Error| {
        AuditError::new(format!("{} could not be read: {error}", file.display()))
    };
    let mut opened = match File::open(file) {
        Ok(opened) => opened,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(refused(error)),
    };
    let (mut fragments, mut base) = (Vec::new(), 0);
    let rest = pieces(&mut opened, |bytes| {
        let parsed = parse(bytes);
        parsed.entries.iter().for_each(&mut offer);
        fragments.extend(parsed.fragments.into_iter().map(|fragment| Fragment {
            offset: base + fragment.offset,
            ..fragment
        }));
        base += bytes.len();
    })
    .map_err(refused)?;
    if !rest.is_empty() {
        fragments.push(Fragment {
            offset: base,
            length: rest.len(),
            sealed: false,
        });
    }
    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_block::BLOCK;
    use crate::audit_column::Column;
    use crate::audit_record::AuditRecord;
    use crate::origin::Origin;
    use crate::program_audit::ProgramAudit;
    use std::collections::BTreeMap;
    use std::fs;

    use xcore::{AuditId, ExecutionPhase, Severity};

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xmip-audit-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("made");
        directory
    }

    fn start(audit: &ProgramAudit, action: &str) {
        audit
            .record(
                action,
                ExecutionPhase::Begin,
                Severity::Information,
                None,
                BTreeMap::new(),
            )
            .expect("recorded");
    }

    fn query(pairs: &[(&str, &str)]) -> AuditQuery {
        AuditQuery::from_pairs(pairs.iter().copied()).expect("a query")
    }

    fn actions(page: &AuditPage) -> Vec<&str> {
        page.records
            .iter()
            .map(|entry| entry.action.as_str())
            .collect()
    }
    #[path = "../../../tests/measured/history.rs"]
    mod history;
    use history::history;

    /// The questions the equality is held to: every column either way,
    /// pages at the start, deep and past the end, each filter, a time
    /// window, what is hidden, one record, one that is not there and an
    /// empty page.
    fn questions(whole: &[AuditEntry]) -> Vec<AuditQuery> {
        let cluster = configure::fixture::test_cluster();
        let (scope, node) = (cluster.scope(), cluster.node_scope(0));
        let (from, to) = (&whole[whole.len() / 3].at, &whole[whole.len() / 2].at);
        let record = &whole[whole.len() * 2 / 3].audit_id;
        let mut asked = Vec::new();
        for column in Column::ALL {
            for order in ["ascending", "descending"] {
                for (offset, limit) in [("0", "200"), ("611", "37"), ("100000", "5")] {
                    asked.push(query(&[
                        ("sort", column.word()),
                        ("order", order),
                        ("offset", offset),
                        ("limit", limit),
                    ]));
                }
            }
        }
        for pairs in [
            &[("location", scope.as_str())][..],
            &[("location", node.as_str()), ("severity", "Error")],
            &[("host", "edge-01"), ("program", "web")],
            &[
                ("pattern", "*/node/*"),
                ("action", "publish"),
                ("offset", "40"),
            ],
            &[("from", from), ("to", to), ("order", "ascending")],
            &[("from", from), ("sort", "program"), ("offset", "300")],
            &[("hidden", "include"), ("sort", "severity")],
            &[("record", record)],
            &[("record", "0192d6c1-0000-7000-8000-000000000000")],
            &[("limit", "0")],
        ] {
            asked.push(query(pairs));
        }
        asked
    }

    /// The page as the reader gave it before the index: every record read,
    /// filtered, sorted whole and cut.
    fn sorted_whole(whole: &[AuditEntry], asked: &AuditQuery) -> Vec<AuditEntry> {
        let mut matched: Vec<&AuditEntry> = whole
            .iter()
            .filter(|entry| asked.standing(entry) && asked.acted(entry))
            .collect();
        matched.sort_by(|left, right| asked.order(left, right));
        matched
            .into_iter()
            .skip(asked.offset)
            .take(asked.limit)
            .cloned()
            .collect()
    }

    #[test]
    fn a_file_that_is_not_there_holds_nothing() {
        let directory = scratch("absent");
        let page = ask(&directory.join("audit.xmip"), &query(&[])).expect("not an error");

        assert_eq!(page, AuditPage::default());
    }

    #[test]
    fn what_was_appended_since_is_read_and_what_was_read_is_kept() {
        let directory = scratch("grows");
        let audit = ProgramAudit::new("probe", Some(&directory));
        let at = configure::fixture::test_cluster().node_scope(0);
        audit.locate(&at);
        let file = audit.file().expect("a file");
        let oldest = query(&[("order", "ascending")]);

        start(&audit, "one");
        assert_eq!(ask(&file, &oldest).expect("read").read, 1);

        start(&audit, "two");
        start(&audit, "three");
        let page = ask(&file, &oldest).expect("read");
        assert_eq!(actions(&page), ["one", "two", "three"]);
        assert_eq!(page.records[2].location.as_deref(), Some(at.as_str()));

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_file_that_got_shorter_is_read_again_from_its_start() {
        let directory = scratch("replaced");
        let audit = ProgramAudit::new("probe", Some(&directory));
        let file = audit.file().expect("a file");
        start(&audit, "one");
        start(&audit, "two");
        assert_eq!(ask(&file, &query(&[])).expect("read").read, 2);

        fs::remove_file(&file).expect("removed");
        start(&audit, "again");
        let page = ask(&file, &query(&[])).expect("read");

        assert_eq!(actions(&page), ["again"]);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn every_page_is_the_one_the_whole_history_gives() {
        let directory = scratch("same");
        let file = directory.join("audit.xmip");
        history(&file, 3_000);
        let whole = parse(&fs::read(&file).expect("read")).entries;
        let mut small = Index::new(192 * 1024);
        small.refresh(&file).expect("indexed");
        assert!(
            small.tallied && small.blocks.len() > 1,
            "merged, still held"
        );
        assert!(small.held() <= 192 * 1024, "{} bytes", small.held());

        for asked in questions(&whole) {
            let scanned = asked.ask(&whole);
            assert_eq!(ask(&file, &asked).expect("asked"), scanned, "{asked:?}");
            let answer = small.ask(&file, &asked).expect("asked");
            let by_index = asked.sort != Column::Summary;
            assert_eq!(answer.is_some(), by_index, "{asked:?}");
            assert!(answer.is_none_or(|page| page == scanned), "{asked:?}");
            if asked.record.is_none() {
                assert_eq!(scanned.records, sorted_whole(&whole, &asked), "{asked:?}");
            }
        }
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn what_is_held_stays_within_the_budget_over_a_long_history() {
        let directory = scratch("budget");
        let file = directory.join("audit.xmip");
        let budget = 256 * 1024;
        let mut index = Index::new(budget);
        let mut most = 0;
        for count in [2_000, 8_000, 20_000] {
            history(&file, count);
            index.refresh(&file).expect("indexed");
            most = most.max(index.held());
            assert!(index.tallied, "{count} records fit");
        }
        let whole = parse(&fs::read(&file).expect("read")).entries;
        for asked in questions(&whole).into_iter().step_by(6) {
            index.ask(&file, &asked).expect("asked");
            most = most.max(index.held());
        }
        assert!(most <= budget, "{most} bytes held of {budget}");
        let (oldest, newest) = (&index.blocks[0], &index.blocks[index.blocks.len() - 1]);
        assert!(newest.records <= BLOCK, "the newest stay short");
        assert!(oldest.records > BLOCK * 8, "the oldest were merged");

        let mut kinds = Index::new(1024);
        kinds.refresh(&file).expect("indexed");
        assert!(
            !kinds.tallied && kinds.held() == 0,
            "the kinds alone outgrew it"
        );
        let _ = fs::remove_dir_all(&directory);
    }
}
