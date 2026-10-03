//! Who produced an audit record: the program, the machine and the process.
//!
//! Observability-model section 3: a record must outlive what produced it and
//! carry enough to say where it came from once that is gone. A process id
//! alone is gone with the process; the program's name and the host are not.
//!
//! A process that belongs somewhere in Xmip says where: the location it
//! declared (ADR-0053 clause 3), `xmip:///<cluster>/node/<node>` for a node,
//! carried on every record it makes so a reader groups records by what they
//! belong to and never by reading a program's name (ADR-0062, amendment
//! 2026-09-29).

use std::fs;

/// The program, host and process an audit record came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Origin {
    /// The program's name as ADR-0053 and its README call it:
    /// `Xmip.Gui.Web`, `xmip-cli`, `xmip-lsp`.
    pub program: String,
    /// The machine's name, `-` when it cannot be read.
    pub host: String,
    /// The operating system's process id.
    pub process: u32,
    /// The scope the process declared it serves (ADR-0053 clause 3):
    /// `xmip:///<cluster>` for a roll or its cluster,
    /// `xmip:///<cluster>/node/<node>` for a node. `None` for a program that
    /// serves no scope — a cmdlet, a web host — whose records a reader shows
    /// under their host.
    pub location: Option<String>,
    /// The process belongs to a run that declared itself hidden (ADR-0028,
    /// amendment 2026-09-30): an operator's view leaves its records out
    /// until asked to include what is hidden, by the one rule
    /// `observe::run::shown`. False for everything else.
    pub hidden: bool,
}

impl Origin {
    /// This process, as `program`.
    #[must_use]
    pub fn here(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            host: host_name(),
            process: std::process::id(),
            location: None,
            hidden: false,
        }
    }
}

/// The machine's name: what Windows and most shells export, else what Linux
/// keeps in its kernel and `/etc`, else `-`.
fn host_name() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .chain(
            ["/proc/sys/kernel/hostname", "/etc/hostname"]
                .iter()
                .filter_map(|path| fs::read_to_string(path).ok()),
        )
        .map(|name| name.trim().to_string())
        .find(|name| !name.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn here_is_this_process_on_a_named_machine() {
        let origin = Origin::here("probe");

        assert_eq!(origin.program, "probe");
        assert_eq!(origin.process, std::process::id());
        assert!(!origin.host.is_empty());
    }
}
