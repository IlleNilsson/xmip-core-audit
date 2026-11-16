//! The operating system's log: where a record goes when audit cannot
//! persist it (ADR-0062 clause 3) — the Windows Event Log, the systemd
//! journal or syslog on Linux, the unified log on macOS.
//!
//! It is the fallback, not a second sink: [`crate::emit::Audit`] writes to
//! it only after the sink refused a record or there was none, and says why
//! first. Which log that is, audit does not know: each is a technology under
//! this capability in `architecture.toml` — `xmip-core-audit-windows-event-log`,
//! `xmip-core-audit-syslog` — and a capability does not depend on its
//! technologies (ADR-0044). The program that runs links the log its
//! platform has and hands it in as it starts ([`hand`]); a .NET program
//! reaches the same one through the runtime's library (`xmip_operate.h`
//! section 9).

use std::sync::OnceLock;

use xcore::Severity;

use crate::AuditError;

/// A log of the operating system's: what audit falls back to.
pub trait OperatingSystemLog: Send + Sync {
    /// Write `text` at `severity`. Answers where it went, in words.
    ///
    /// # Errors
    /// The log refused it, with the reason in words.
    fn write(&self, severity: Severity, text: &str) -> Result<String, AuditError>;
}

/// The log this process was handed.
static HANDED: OnceLock<Box<dyn OperatingSystemLog>> = OnceLock::new();

/// Hand this process's audit the operating system's log, as the program
/// starts. A process is handed one log: the first one handed stands.
pub fn hand(log: impl OperatingSystemLog + 'static) {
    let _ = HANDED.set(Box::new(log));
}

/// Write `text` at `severity` to the log this process was handed. Answers
/// where it went, in words.
///
/// # Errors
/// No log was handed, or the one handed refused it.
pub fn write(severity: Severity, text: &str) -> Result<String, AuditError> {
    match HANDED.get() {
        Some(log) => log.write(severity, text),
        None => Err(AuditError::new(
            "this program handed its audit no operating system's log",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log that says which it is, so no test writes to this machine's.
    struct Said(&'static str);

    impl OperatingSystemLog for Said {
        fn write(&self, _: Severity, text: &str) -> Result<String, AuditError> {
            Ok(format!("{} took {text}", self.0))
        }
    }

    #[test]
    fn the_first_log_handed_stands() {
        hand(Said("the first"));
        hand(Said("the second"));

        assert_eq!(
            write(Severity::Error, "it").expect("written"),
            "the first took it"
        );
    }
}
