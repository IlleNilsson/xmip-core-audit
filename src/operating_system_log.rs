//! The operating system's log: where a record goes when audit cannot
//! persist it (ADR-0062 clause 3) — the Windows Event Log, the systemd
//! journal or syslog on Linux, the unified log on macOS.
//!
//! It is the fallback, not a second sink: [`crate::emit::Audit`] is the
//! only caller, and only after the configured sink refused a record or
//! there was none. Each platform's writer is a technology under this
//! capability in `architecture.toml`; they live here because the fallback
//! is the capability's own rule and a capability does not depend on its
//! technologies (ADR-0044).
//!
//! On Unix the record is one datagram to the local syslog socket, which the
//! journal reads on a systemd machine and the unified log on macOS; no unsafe
//! reaches it. On Windows the Event Log has no interface but a C one, called
//! from `windows_event_log.rs`, the one file in this crate that may hold
//! unsafe code (ADR-0050, amendment 2026-09-25).

use crate::AuditError;
use crate::audit_record::AuditRecord;

/// The operating system's log on this machine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperatingSystemLog;

impl OperatingSystemLog {
    /// Write `record` to the operating system's log, opening with `why` it
    /// is there. Answers where it went, in words.
    ///
    /// # Errors
    /// The operating system's log refused it too, or this platform has none
    /// this crate writes to.
    pub fn write(record: &AuditRecord, why: &str) -> Result<String, AuditError> {
        let text = format!("{why} {}", record.line());

        write(record, &text)
    }
}

#[cfg(windows)]
fn write(record: &AuditRecord, text: &str) -> Result<String, AuditError> {
    crate::windows_event_log::write(record.severity, text)
}

#[cfg(unix)]
fn write(record: &AuditRecord, text: &str) -> Result<String, AuditError> {
    crate::syslog::write(record.severity, text)
}

#[cfg(not(any(windows, unix)))]
fn write(_: &AuditRecord, _: &str) -> Result<String, AuditError> {
    Err(AuditError::new(
        "this platform has no operating system log Xmip writes to",
    ))
}
