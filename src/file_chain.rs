//! Where each writer's audit chain stands in a file the file sink appends
//! to (ADR-0070 clause 5): the number and the digest of its last record,
//! which the next record it appends carries as the one before it.
//!
//! Every program of a writer may append to one file, one process after
//! another and two at once, so the sink appends holding [`LOCK_NAME`]
//! beside the file, and what this process knows of the file is brought up
//! to date under it: what was appended since it last looked is read, never
//! the whole history. A writer this process has not met yet is found by
//! reading back from the end of the file to its last record: the last
//! record of its chain, wherever the writer restarted. A file that got
//! shorter was replaced, and is looked at again.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::audit_chain::{Digest, FIRST};
use crate::audit_entry::{AuditEntry, parse};

/// The file beside `audit.toml` an appender holds while it appends: the
/// operating system's own lock, which ends with the process.
pub const LOCK_NAME: &str = "audit.lock";

/// How much of the file's end is read first to find a writer's last
/// record; four times more each time it is not there.
const WINDOW: u64 = 64 * 1024;

/// A chain's last record: its number and its digest. Number 0 and
/// [`FIRST`] where the writer has none.
pub(crate) type Head = (u64, Digest);

/// What this process knows of one file: how far it has looked, and the
/// head of each writer it has met.
#[derive(Default)]
struct Tail {
    /// Whether it has looked at all.
    looked: bool,
    length: u64,
    heads: HashMap<String, Head>,
}

fn tails() -> &'static Mutex<HashMap<PathBuf, Tail>> {
    static TAILS: OnceLock<Mutex<HashMap<PathBuf, Tail>>> = OnceLock::new();
    TAILS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The head of `writer`'s chain in the file at `path`, read while the
/// caller holds the lock, through a handle of its own that only reads: the
/// file is open for writing only for the write.
pub(crate) fn head(path: &Path, writer: &str) -> io::Result<Head> {
    let mut file = match File::open(path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let length = match &file {
        Some(file) => file.metadata()?.len(),
        None => 0,
    };
    let mut all = tails().lock().unwrap_or_else(PoisonError::into_inner);
    let tail = all.entry(path.to_path_buf()).or_default();
    if length < tail.length {
        *tail = Tail::default();
    }
    if let Some(file) = file.as_mut()
        && tail.looked
        && length > tail.length
    {
        let appended = read_from(file, tail.length, length)?;
        for entry in parse(&appended).0 {
            if let Some(writer) = entry.writer.clone() {
                tail.heads.insert(writer, head_of(&entry));
            }
        }
    }
    tail.length = length;
    tail.looked = true;
    if let Some(head) = tail.heads.get(writer) {
        return Ok(*head);
    }
    let head = match file.as_mut() {
        Some(file) => from_the_end(file, length, writer)?,
        None => (0, FIRST),
    };
    tail.heads.insert(writer.to_string(), head);
    Ok(head)
}

/// `writer` appended its record `head` to `path`, which is now `length`
/// long.
pub(crate) fn appended(path: &Path, writer: &str, head: Head, length: u64) {
    let mut all = tails().lock().unwrap_or_else(PoisonError::into_inner);
    let tail = all.entry(path.to_path_buf()).or_default();
    tail.length = length;
    tail.looked = true;
    tail.heads.insert(writer.to_string(), head);
}

fn head_of(entry: &AuditEntry) -> Head {
    (
        entry.position.unwrap_or_default(),
        entry.digest.unwrap_or(FIRST),
    )
}

/// The text from `start` to `end`.
fn read_from(file: &mut File, start: u64, end: u64) -> io::Result<String> {
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(end - start).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `writer`'s last record, read back from the end of the file a window at
/// a time, from the first table that starts whole in the window.
fn from_the_end(file: &mut File, length: u64, writer: &str) -> io::Result<Head> {
    let mut window = WINDOW;
    loop {
        let start = length.saturating_sub(window);
        let text = read_from(file, start, length)?;
        let from = if start == 0 {
            0
        } else {
            text.find("\n[[record]]\n").map_or(text.len(), |at| at + 1)
        };
        let found = parse(&text[from..])
            .0
            .iter()
            .rev()
            .find(|entry| entry.writer.as_deref() == Some(writer))
            .map(head_of);
        match found {
            Some(head) => return Ok(head),
            None if start == 0 => return Ok((0, FIRST)),
            None => window = window.saturating_mul(4),
        }
    }
}

/// Forget what this process knows of `path`, as a process started anew
/// would not know it.
#[cfg(test)]
pub(crate) fn forget(path: &Path) {
    tails()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(path);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use xcore::{ExecutionPhase, Severity};

    use super::*;
    use crate::audit_chain::{Break, Verdict, chains};
    use crate::program_audit::ProgramAudit;

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xmip-audit-chain-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        directory
    }

    fn act(audit: &ProgramAudit, action: &str) {
        let said = BTreeMap::from([("said".to_string(), "a \"quoted\"\nvalue".to_string())]);
        audit
            .record(
                action,
                ExecutionPhase::Begin,
                Severity::Information,
                None,
                said,
            )
            .expect("recorded");
    }

    /// The file's tables, each as written.
    fn tables(path: &Path) -> Vec<String> {
        let text = fs::read_to_string(path).expect("read");
        text.split_inclusive("\n\n").map(str::to_string).collect()
    }

    fn verdicts(path: &Path, writers: &[&str]) -> Vec<Verdict> {
        let text = fs::read_to_string(path).expect("read");
        chains(&parse(&text).0, writers)
    }

    /// Four records of the program `probe`, in `directory`.
    fn four(directory: &Path) -> (ProgramAudit, PathBuf) {
        let audit = ProgramAudit::new("probe", Some(directory));
        for action in ["one", "two", "three", "four"] {
            act(&audit, action);
        }
        let path = audit.file().expect("a file");
        (audit, path)
    }

    #[test]
    fn every_record_carries_its_place_and_a_whole_chain_verifies() {
        let directory = scratch("whole");
        let (_, path) = four(&directory);
        let text = fs::read_to_string(&path).expect("read");
        assert_eq!(text.matches("\nwriter = \"probe\"\n").count(), 4, "{text}");
        assert!(text.contains("position = \"4\"\n"), "{text}");
        assert!(text.contains(&format!("previous = \"{}\"", "0".repeat(64))));

        let verdict = &verdicts(&path, &["probe"])[0];
        assert!(verdict.whole(), "{}", verdict.said());
        assert_eq!(verdict.records, 4);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_deleted_a_changed_and_a_reordered_record_are_each_found_where_they_are() {
        let directory = scratch("broken");
        let (_, path) = four(&directory);
        let written = tables(&path);
        let id = |table: &str| parse(table).0[0].audit_id.clone();

        let deleted = [&written[0], &written[1], &written[3]];
        fs::write(&path, deleted.map(String::as_str).concat()).expect("written");
        let broken = verdicts(&path, &["probe"]).remove(0).broken;
        let from = 3;
        let gone = Break::Deleted {
            record: id(&written[3]),
            position: 4,
            from,
            to: from,
        };
        assert_eq!(broken, Some(gone));

        let changed = written[1].replace("action = \"two\"", "action = \"zwei\"");
        fs::write(
            &path,
            [&written[0], &changed, &written[2]]
                .map(String::as_str)
                .concat(),
        )
        .expect("written");
        let broken = verdicts(&path, &["probe"]).remove(0).broken;
        assert_eq!(
            broken,
            Some(Break::Changed {
                record: id(&written[1]),
                position: 2
            })
        );

        let reordered = [&written[0], &written[2], &written[1], &written[3]];
        fs::write(&path, reordered.map(String::as_str).concat()).expect("written");
        let verdict = verdicts(&path, &["probe"]).remove(0);
        let moved = Break::OutOfOrder {
            record: id(&written[1]),
            position: 2,
            after: 3,
        };
        assert_eq!(verdict.broken, Some(moved));
        assert!(verdict.said().starts_with("FAILED: "), "{}", verdict.said());
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_writer_started_again_continues_its_chain_from_its_last_record() {
        let directory = scratch("restart");
        let (_, path) = four(&directory);
        let other = ProgramAudit::new("another", Some(&directory));
        act(&other, "between");

        forget(&path);
        let again = ProgramAudit::new("probe", Some(&directory));
        act(&again, "five");

        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("position = \"5\"\n"), "{text}");
        let verdict = &verdicts(&path, &["probe"])[0];
        assert!(verdict.whole(), "{}", verdict.said());
        assert_eq!(verdict.records, 5);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn two_writers_chains_are_each_their_own() {
        let directory = scratch("two");
        let node = configure::fixture::test_cluster().node_scope(0);
        let (first, second) = (
            ProgramAudit::new("probe", Some(&directory)),
            ProgramAudit::new("probe", Some(&directory)),
        );
        second.locate(&node);
        for action in ["one", "two", "three"] {
            act(&first, action);
            act(&second, action);
        }
        let path = first.file().expect("a file");
        let written = tables(&path);
        let without = [
            &written[0],
            &written[1],
            &written[3],
            &written[4],
            &written[5],
        ];
        fs::write(&path, without.map(String::as_str).concat()).expect("written");

        let verdicts = verdicts(&path, &["probe", &node]);
        assert!(!verdicts[0].whole(), "the program's lost its second");
        assert!(verdicts[1].whole(), "{}", verdicts[1].said());
        assert_eq!(verdicts[1].records, 3);
        let _ = fs::remove_dir_all(&directory);
    }
}
