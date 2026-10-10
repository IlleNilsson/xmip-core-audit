//! The file sink: records appended to one TOML file in a directory — the
//! default sink of every Xmip program (ADR-0062), and the `file` technology
//! the manifest names under this capability.
//!
//! Which directory is decided here and nowhere else: the one a program was
//! told (its configuration, a node's area), else [`DIRECTORY_VARIABLE`],
//! else none — and with none, [`crate::emit::Audit`] sends the record to
//! the operating system's log. The estate's own tooling sets the variable
//! to `.local-work/audit` for everything it starts.
//!
//! Each record is appended in its writer's audit chain, holding the lock
//! beside the file (`crate::file_chain`; ADR-0070 clause 5).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::audit_record::AuditRecord;
use crate::file_chain::{self, LOCK_NAME};
use crate::{AuditError, AuditSink};

/// The environment variable that names the audit directory when a program
/// was told none.
pub const DIRECTORY_VARIABLE: &str = "XMIP_AUDIT_DIRECTORY";

/// The file in that directory every program appends to: one place to read.
pub const FILE_NAME: &str = "audit.toml";

/// Records appended to [`FILE_NAME`] in one directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSink {
    directory: PathBuf,
}

impl FileSink {
    /// A sink over `directory`, created on the first write.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// The sink a program writes to: `stated` when it is given and not
    /// blank, else the directory [`DIRECTORY_VARIABLE`] names, else none.
    #[must_use]
    pub fn stated(stated: Option<&Path>) -> Option<Self> {
        stated
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .or_else(|| {
                std::env::var_os(DIRECTORY_VARIABLE)
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            })
            .map(Self::new)
    }

    /// The file the records go to.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.directory.join(FILE_NAME)
    }
}

impl AuditSink for FileSink {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let refused = |error: std::io::Error| {
            AuditError::new(format!(
                "{} could not be written: {error}",
                self.path().display()
            ))
        };

        fs::create_dir_all(&self.directory).map_err(refused)?;
        self.chained(record).map_err(refused)
    }
}

impl FileSink {
    /// Append `record` in its writer's audit chain (ADR-0070 clause 5):
    /// holding the lock beside the file, read where the chain stands and
    /// append the record after it, in one write of the whole table.
    fn chained(&self, record: &AuditRecord) -> std::io::Result<()> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.directory.join(LOCK_NAME))?;
        lock.lock()?;
        let path = self.path();
        let writer = record.origin.writer();
        let (position, previous) = file_chain::head(&path, &writer)?;
        let (table, own) = record.chained(&writer, position + 1, &previous);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(table.as_bytes())?;
        let length = file.metadata()?.len();
        drop(file);
        file_chain::appended(&path, &writer, (position + 1, own), length);
        // The lock ends as it is dropped, after the write.
        drop(lock);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::Origin;
    use std::collections::BTreeMap;
    use xcore::{AuditId, ExecutionPhase, Severity};

    fn record(action: &str) -> AuditRecord {
        AuditRecord {
            audit_id: AuditId::new(7),
            origin: Origin::here("probe"),
            scope: None,
            action: action.to_string(),
            phase: ExecutionPhase::Begin,
            severity: Severity::Information,
            timestamp_unix_nanos: 0,
            message: None,
            properties: BTreeMap::new(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("xmip-audit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn records_append_to_one_file_that_reads_as_toml_tables() {
        let directory = scratch("append");
        let sink = FileSink::new(&directory);

        sink.write(&record("start")).expect("written");
        sink.write(&record("stop")).expect("written");

        let text = fs::read_to_string(sink.path()).expect("read");
        assert_eq!(text.matches("[[record]]").count(), 2, "{text}");
        assert!(text.contains("action = \"start\""), "{text}");
        assert!(text.contains("action = \"stop\""), "{text}");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_directory_that_cannot_be_made_is_refused_with_the_path() {
        let directory = scratch("blocked");
        fs::create_dir_all(&directory).expect("made");
        let blocker = directory.join("a-file");
        fs::write(&blocker, b"not a directory").expect("written");

        let error = FileSink::new(blocker.join("audit"))
            .write(&record("start"))
            .expect_err("a file stands where the directory would be");

        assert!(
            error.to_string().contains("could not be written"),
            "{error}"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_stated_directory_wins_and_a_blank_one_is_no_statement() {
        let stated = FileSink::stated(Some(Path::new("stated"))).expect("stated");
        assert_eq!(stated.path(), Path::new("stated").join(FILE_NAME));

        // Blank is not a statement; what is left is the variable, which this
        // test neither sets nor clears, so it only asks the answer be one.
        let blank = FileSink::stated(Some(Path::new("")));
        let from_variable = FileSink::stated(None);
        assert_eq!(blank, from_variable);
    }
}
