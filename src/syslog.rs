//! Syslog on the local machine: one datagram to its socket, as the C
//! library's `syslog(3)` sends one — `<PRI>xmip[pid]: text`.
//!
//! On a systemd machine `/dev/log` is the journal's own socket, so the
//! record is in the journal (`journalctl -t xmip`); elsewhere a syslog daemon
//! reads it; on macOS `/var/run/syslog` feeds the unified log. The `syslog`
//! technology under this capability in `architecture.toml`.

use std::os::unix::net::UnixDatagram;

use xcore::Severity;

use crate::AuditError;

/// Where the local syslog listens, in the order they are tried: Linux,
/// macOS, the BSDs.
const SOCKETS: [&str; 3] = ["/dev/log", "/var/run/syslog", "/var/run/log"];

/// The identifier every Xmip record is logged under.
const TAG: &str = "xmip";

/// RFC 5424's facility for user-level messages.
const FACILITY_USER: u8 = 1;

/// A datagram longer than this is cut: every local syslog takes this much,
/// and a record that needs more has said what matters by then.
const MOST: usize = 8 * 1024;

/// Send `text` at `severity`. Answers the socket that took it.
pub(crate) fn write(severity: Severity, text: &str) -> Result<String, AuditError> {
    // RFC 5424 severities: error 3, warning 4, informational 6.
    let level: u8 = match severity {
        Severity::Error => 3,
        Severity::Warning => 4,
        Severity::Information => 6,
    };
    let mut datagram = format!(
        "<{}>{TAG}[{}]: {text}",
        FACILITY_USER * 8 + level,
        std::process::id()
    );

    if datagram.len() > MOST {
        let mut end = MOST;
        while !datagram.is_char_boundary(end) {
            end -= 1;
        }
        datagram.truncate(end);
    }

    let socket = UnixDatagram::unbound()
        .map_err(|error| AuditError::new(format!("no socket for syslog: {error}")))?;
    let mut refusals = Vec::new();

    for path in SOCKETS {
        match socket.send_to(datagram.as_bytes(), path) {
            Ok(_) => return Ok(format!("syslog at {path}")),
            Err(error) => refusals.push(format!("{path}: {error}")),
        }
    }

    Err(AuditError::new(format!(
        "no local syslog took it ({})",
        refusals.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "writes to this machine's syslog or journal; run with --ignored to prove it"]
    fn an_entry_reaches_the_local_syslog() {
        let said = write(Severity::Error, "written by xmip-core-audit's own test").expect("sent");

        assert!(said.starts_with("syslog at "), "{said}");
    }
}
