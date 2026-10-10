//! The audit store read: the file [`crate::file_sink::FileSink`] appends to,
//! read back into [`AuditEntry`] records (ADR-0062, amendment 2026-09-29).
//!
//! The file only grows, so a reader keeps what it read and, the next time,
//! reads what was appended since: a view that reads again on every change of
//! a cluster reads a few hundred bytes, not the whole history. A file that
//! got shorter was replaced, and is read again from its start. What is kept
//! is kept once per process and per file, and shared by every caller.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::AuditError;
use crate::audit_entry::{AuditEntry, parse};
use crate::file_sink::FileSink;

/// What was read of one file, and how far.
#[derive(Clone, Default)]
struct Held {
    read: u64,
    entries: Arc<Vec<AuditEntry>>,
}

fn held() -> &'static Mutex<HashMap<PathBuf, Held>> {
    static HELD: OnceLock<Mutex<HashMap<PathBuf, Held>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The file a reader reads: the one a program writing into `directory`
/// would write, by the one rule ([`FileSink::stated`]) — `directory` when it
/// is given and not blank, else `XMIP_AUDIT_DIRECTORY`, else none.
#[must_use]
pub fn stated(directory: Option<&Path>) -> Option<PathBuf> {
    FileSink::stated(directory).map(|sink| sink.path())
}

/// Every record `file` holds, oldest first. A file that is not there holds
/// none: nothing has been audited there yet.
///
/// # Errors
/// The file is there and could not be read, with the path and the reason.
pub fn read(file: &Path) -> Result<Arc<Vec<AuditEntry>>, AuditError> {
    let refused = |error: std::io::Error| {
        AuditError::new(format!("{} could not be read: {error}", file.display()))
    };

    let mut opened = match File::open(file) {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Arc::new(Vec::new()));
        }
        Err(error) => return Err(refused(error)),
    };
    let length = opened.metadata().map_err(refused)?.len();

    let mut all = held()
        .lock()
        .map_err(|_| AuditError::new("the audit reader's cache was poisoned"))?;
    let kept = all.entry(file.to_path_buf()).or_default();

    if length < kept.read {
        *kept = Held::default();
    }
    if length == kept.read {
        return Ok(Arc::clone(&kept.entries));
    }

    opened.seek(SeekFrom::Start(kept.read)).map_err(refused)?;
    let mut appended = Vec::new();
    opened.read_to_end(&mut appended).map_err(refused)?;
    let text = String::from_utf8_lossy(&appended);
    let (entries, read) = parse(&text);

    if read > 0 {
        Arc::make_mut(&mut kept.entries).extend(entries);
        kept.read += read as u64;
    }

    Ok(Arc::clone(&kept.entries))
}

/// Every record `file` holds, read whole from its bytes now, past what this
/// process kept: what a verification of the audit chains walks (ADR-0070
/// clause 5), since a record changed in place leaves the file as long as it
/// was and [`read`] would answer what it kept.
///
/// # Errors
/// As [`read`].
pub fn read_whole(file: &Path) -> Result<Arc<Vec<AuditEntry>>, AuditError> {
    match std::fs::read(file) {
        Ok(bytes) => Ok(Arc::new(parse(&String::from_utf8_lossy(&bytes)).0)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Arc::new(Vec::new())),
        Err(error) => Err(AuditError::new(format!(
            "{} could not be read: {error}",
            file.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program_audit::ProgramAudit;
    use std::collections::BTreeMap;
    use std::fs;
    use xcore::{ExecutionPhase, Severity};

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xmip-audit-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
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

    #[test]
    fn a_file_that_is_not_there_holds_nothing() {
        let directory = scratch("absent");
        let entries = read(&directory.join("audit.toml")).expect("nothing, not an error");

        assert!(entries.is_empty());
    }

    #[test]
    fn what_was_appended_since_is_read_and_what_was_read_is_kept() {
        let directory = scratch("grows");
        let audit = ProgramAudit::new("probe", Some(&directory));
        let at = configure::fixture::test_cluster().node_scope(0);
        audit.locate(&at);
        let file = audit.file().expect("a file");

        start(&audit, "one");
        assert_eq!(read(&file).expect("read").len(), 1);

        start(&audit, "two");
        start(&audit, "three");
        let entries = read(&file).expect("read");
        let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
        assert_eq!(actions, ["one", "two", "three"]);
        assert_eq!(entries[2].location.as_deref(), Some(at.as_str()));

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_file_that_got_shorter_is_read_again_from_its_start() {
        let directory = scratch("replaced");
        let audit = ProgramAudit::new("probe", Some(&directory));
        let file = audit.file().expect("a file");
        start(&audit, "one");
        start(&audit, "two");
        assert_eq!(read(&file).expect("read").len(), 2);

        fs::remove_file(&file).expect("removed");
        start(&audit, "again");
        let entries = read(&file).expect("read");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "again");
        let _ = fs::remove_dir_all(&directory);
    }
}
