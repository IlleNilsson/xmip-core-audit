//! The Windows Event Log: an entry in the Application log, event 1000, under
//! the event source `XMIP_EVENT_SOURCE` (`xmip_operate.h` section 9,
//! ADR-0062 clause 3), written through the Event Log's own C interface.
//!
//! Registering the source needs elevation once; the prerequisite installer
//! does it. Until it has, an entry is written under the Application log's
//! existing `.NET Runtime` source, whose event 1000 shows the text as given,
//! and its first sentence says why. The `windows-event-log` technology under
//! this capability in `architecture.toml`.
//!
//! The one file in this crate that may hold unsafe code (ADR-0050, amendment
//! 2026-09-25): the Event Log and the registry are C interfaces and are
//! reached no other way. Every block says where its pointers come from, how
//! long they live and who frees what they hand back.
#![allow(unsafe_code)]

use std::ptr;

use abi::operate::audit::{EVENT_SOURCE, EVENT_SOURCE_UNREGISTERED};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    RegisterEventSourceW, ReportEventW,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};
use xcore::Severity;

use crate::AuditError;

/// The source an entry goes under while `EVENT_SOURCE` is not registered.
const STAND_IN: &str = ".NET Runtime";

/// Where the Application log's sources are registered.
const SOURCES: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application";

/// Every Xmip entry is event 1000: the id whose message is the text as given,
/// under the registered source and under the stand-in alike.
const EVENT: u32 = 1000;

/// The Event Log's limit on one entry's text is 31 839 characters.
const MOST: usize = 31_000;

/// Write `text` at `severity`. Answers the log and source that took it.
pub(crate) fn write(severity: Severity, text: &str) -> Result<String, AuditError> {
    let kind = match severity {
        Severity::Error => EVENTLOG_ERROR_TYPE,
        Severity::Warning => EVENTLOG_WARNING_TYPE,
        Severity::Information => EVENTLOG_INFORMATION_TYPE,
    };
    let (source, entry) = if registered(EVENT_SOURCE) {
        (EVENT_SOURCE, text.to_string())
    } else {
        (STAND_IN, format!("{EVENT_SOURCE_UNREGISTERED} {text}"))
    };
    let entry: String = entry.chars().take(MOST).collect();

    report(source, kind, &entry)?;
    Ok(format!(
        "the Windows Event Log, Application, source {source}"
    ))
}

/// Whether `source` is registered under the Application log.
fn registered(source: &str) -> bool {
    let path = wide(&format!(r"{SOURCES}\{source}"));
    let mut key: HKEY = ptr::null_mut();

    // SAFETY: `path` is a NUL-terminated UTF-16 string owned by this frame
    // and outlives the call; `key` is a local the call writes the opened
    // key's handle into. HKEY_LOCAL_MACHINE is a predefined key, never freed.
    let opened =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &raw mut key) };

    if opened != ERROR_SUCCESS {
        return false;
    }

    // SAFETY: `key` is the handle RegOpenKeyExW opened above and nothing else
    // holds it; this closes it once, and it is not used again.
    unsafe { RegCloseKey(key) };
    true
}

/// One entry under `source`.
fn report(source: &str, kind: u16, text: &str) -> Result<(), AuditError> {
    let name = wide(source);
    let message = wide(text);

    // SAFETY: `name` is a NUL-terminated UTF-16 string owned by this frame and
    // outlives the call; a null server name is this machine. The handle
    // returned is this process's and is released below by
    // DeregisterEventSource, exactly once.
    let log = unsafe { RegisterEventSourceW(ptr::null(), name.as_ptr()) };

    if log.is_null() {
        return Err(AuditError::new(format!(
            "the Windows Event Log refused the source {source}: {}",
            std::io::Error::last_os_error()
        )));
    }

    let strings = [message.as_ptr()];

    // SAFETY: `log` is the live handle registered above. `strings` holds one
    // pointer to `message`, a NUL-terminated UTF-16 string owned by this
    // frame, and both outlive the call; the count passed is that one. No user
    // SID (null) and no raw data (null, size 0). The Event Log copies what it
    // keeps; nothing it is handed is freed by it.
    let reported = unsafe {
        ReportEventW(
            log,
            kind,
            0,
            EVENT,
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        )
    };
    let failure = std::io::Error::last_os_error();

    // SAFETY: `log` is the handle RegisterEventSourceW returned above; it is
    // released here once and not used again.
    unsafe { DeregisterEventSource(log) };

    if reported == 0 {
        return Err(AuditError::new(format!(
            "the Windows Event Log refused the entry: {failure}"
        )));
    }

    Ok(())
}

/// `text` as NUL-terminated UTF-16, the only text the Windows API reads.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_that_is_not_there_is_not_registered_and_the_stand_in_is() {
        assert!(!registered(
            "Xmip audit test source that is never registered"
        ));
        assert!(registered(STAND_IN), "{STAND_IN} ships with Windows");
    }

    #[test]
    fn text_crosses_as_nul_terminated_utf_16() {
        assert_eq!(wide("Xö"), vec![0x58, 0xf6, 0]);
    }

    #[test]
    #[ignore = "writes to this machine's Windows Event Log; run with --ignored to prove it"]
    fn an_entry_reaches_the_event_log() {
        let said = write(
            Severity::Information,
            "written by xmip-core-audit's own test",
        )
        .expect("written");

        assert!(
            said.starts_with("the Windows Event Log, Application"),
            "{said}"
        );
    }

    #[test]
    #[ignore = "writes to this machine's Windows Event Log; run with --ignored to prove it"]
    fn an_entry_under_the_stand_in_says_why() {
        let text = format!("{EVENT_SOURCE_UNREGISTERED} written by xmip-core-audit's own test");

        report(STAND_IN, EVENTLOG_WARNING_TYPE, &text).expect("written");
    }
}
