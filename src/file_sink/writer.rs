//! One audit file's writer in this process (`super`): every record handed
//! to it is appended in its writer's chain, in the order handed over, and
//! on the disk before it is said written (ADR-0062, amendment 2026-11-13).
//!
//! **One flush for what waits together.** A caller hands its record over
//! and, where no group is being written, writes every record waiting — its
//! own among them — in one append and one durable flush; a caller handing
//! one over while a group is being written waits for the next group, which
//! the first of them writes. So a record waits at most for the flush under
//! way and its own, never for one flush per record before it.
//!
//! **Opened for each group, held by none between.** The lock beside the
//! file is taken for each group, as every program of the estate takes it
//! (`file_chain::LOCK_NAME`), and the file is opened to append and closed
//! again, so a reader opening it is never kept out between groups. It is
//! read only where this process did not leave it as it stands
//! (`file_chain::whole_at`): its end, to seal a table another write left
//! unfinished, and what another process appended. Reading a file just
//! written is what an operating system's file scanner waits on, 37 ms a
//! record on Windows on 2026-11-13, when the durable write itself was
//! 1.6 ms.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use xcore::audit_chain::Head;
use xcore::lock::Locked;
use xcore::wake::Wake;

use super::FILE_NAME;
use crate::audit_fragment::{BOUNDARY, sealing};
use crate::audit_record::AuditRecord;
use crate::file_chain::{self, LOCK_NAME};

/// The writer of one directory's audit file.
pub(super) struct Writer {
    directory: PathBuf,
    state: Mutex<State>,
    /// Signaled as a group is written.
    told: Wake,
}

#[derive(Default)]
struct State {
    /// Handed over and waiting for the next group, each with its number.
    waiting: Vec<(u64, AuditRecord)>,
    /// The number the next record handed over gets.
    next: u64,
    /// Whether a caller is writing a group now.
    writing: bool,
    /// What became of each record written, by its number, until its caller
    /// takes it.
    kept: HashMap<u64, Result<(), String>>,
}

/// The writer of the audit file in `directory`, the one of this process.
pub(super) fn of(directory: &Path) -> Arc<Writer> {
    static WRITERS: LazyLock<Mutex<HashMap<PathBuf, Arc<Writer>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let mut writers = WRITERS.locked();
    Arc::clone(writers.entry(directory.to_path_buf()).or_insert_with(|| {
        Arc::new(Writer {
            directory: directory.to_path_buf(),
            state: Mutex::new(State::default()),
            told: Wake::new(),
        })
    }))
}

impl Writer {
    /// `record` appended and on the disk, with every record waiting with
    /// it; or why the group it was written in was not.
    pub(super) fn keep(&self, record: &AuditRecord) -> Result<(), String> {
        let mut state = self.state.locked();
        let mine = state.next;
        state.next += 1;
        state.waiting.push((mine, record.clone()));
        loop {
            if let Some(kept) = state.kept.remove(&mine) {
                return kept;
            }
            if state.writing {
                state = self.told.wait(&self.state, state);
                continue;
            }
            state.writing = true;
            let group = std::mem::take(&mut state.waiting);
            drop(state);
            let records: Vec<&AuditRecord> = group.iter().map(|(_, record)| record).collect();
            let written = catch_unwind(AssertUnwindSafe(|| self.written(&records)))
                .unwrap_or_else(|_| Err(io::Error::other("its write panicked")))
                .map_err(|error| error.to_string());
            state = self.state.locked();
            for (number, _) in &group {
                state.kept.insert(*number, written.clone());
            }
            state.writing = false;
            self.told.notify_all();
        }
    }

    /// `records` appended in one write, in order, each in its writer's
    /// chain, after the seal an unfinished table needs, and flushed to the
    /// disk; holding the lock beside the file throughout.
    fn written(&self, records: &[&AuditRecord]) -> io::Result<()> {
        let lock = self.locked()?;
        let path = self.directory.join(FILE_NAME);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        let length = file.metadata()?.len();
        let mut text = if file_chain::whole_at(&path, length) {
            String::new()
        } else {
            seal(&path, length)?.unwrap_or_default()
        };
        let mut heads: HashMap<String, Head> = HashMap::new();
        for record in records {
            let writer = record.origin.writer();
            let head = match heads.get(&writer) {
                Some(head) => *head,
                None => file_chain::head(&path, length, &writer)?,
            };
            let (position, previous) = head.next();
            let (table, own) = record.chained(&writer, position, &previous);
            text.push_str(&table);
            heads.insert(writer, head.after(own));
        }
        file.write_all(text.as_bytes())?;
        file.sync_data()?;
        drop(file);
        if length == 0 {
            durable_entry(&self.directory)?;
        }
        let length = length + u64::try_from(text.len()).unwrap_or(u64::MAX);
        for (writer, head) in heads {
            file_chain::appended(&path, &writer, head, length);
        }
        // The lock ends as it is dropped, after the flush.
        drop(lock);
        Ok(())
    }

    /// The lock beside the file, held: the directory made where it is not
    /// there yet.
    fn locked(&self) -> io::Result<File> {
        let at = self.directory.join(LOCK_NAME);
        let open = || {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&at)
        };
        let lock = match open() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.directory)?;
                open()?
            }
            opened => opened?,
        };
        lock.lock()?;
        Ok(lock)
    }
}

/// What ends the unfinished table the file at `path`, `length` long, ends
/// in, where it ends in one: its bytes are kept as written and the seal
/// follows them, so they stand apart as a fragment and the record after
/// them is not written onto them (`crate::audit_fragment`). Read through a
/// handle that only reads.
fn seal(path: &Path, length: u64) -> io::Result<Option<String>> {
    if length == 0 {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    let mut end = [0; BOUNDARY.len()];
    let last = end.len().min(usize::try_from(length).unwrap_or(usize::MAX));
    file.seek(SeekFrom::Start(
        length - u64::try_from(last).unwrap_or_default(),
    ))?;
    file.read_exact(&mut end[..last])?;
    Ok(sealing(&end[..last]))
}

/// The directory's entry for a file just made, on the disk too: what a
/// flush of the file itself does not cover where the directory is a file
/// of its own (Unix).
#[cfg(unix)]
fn durable_entry(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

/// Elsewhere the file's own flush is all there is: the standard library
/// opens no directory to flush on Windows.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
const fn durable_entry(_directory: &Path) -> io::Result<()> {
    Ok(())
}
