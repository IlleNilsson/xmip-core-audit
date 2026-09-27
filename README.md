# xmip-core-audit

The audit record: the persistent accountability record of what Xmip did,
where, by whom, why, when and with what outcome. An `AuditRecord` carries its
origin — the program, host and process — its scope when it belongs to a
Message's execution (`execution_scope::ExecutionScope`, naming the
`ArtifactRef` that acted), its action, phase and severity; an `AuditPolicy` decides
record or suppress; an `AuditSink` persists; `Audit` puts the three together.

Audit is cross-cutting, not a stage, and it holds no payloads — retention
does. It never becomes the execution bottleneck: an action emits an envelope
and this crate persists independently of it. Failures are always audited and
failure records are always persisted; that is not policy, and `Audit` holds
it: a record in the Failure phase, or an Error at any phase, is kept whatever
policy says.

## Every Xmip program audits (ADR-0062)

Not the runtime alone: the web and desktop monitors, the command line, both
PowerShell modules, the Playground's processes, the language server and the
estate's own tooling record what they start and stop, every act an operator
takes through them and every failure. A Rust program holds a
`program_audit::ProgramAudit` (`record`, `failed`, `watch_panics`); a .NET
program and PowerShell reach the same one through the runtime's library,
`xmip_operate.h` section 9 (`xmip_audit_v1`), and `Xmip.Surface`'s
`ProgramAudit`. No program writes a record of its own.

A record made where the caller must not wait for a disk — an Event's
delivery, a subscription closed — is handed to `keeper`, one thread in the
process that keeps records in the order they were handed over
(`keeper::later`); `keeper::settle` waits for them, and a direct
`ProgramAudit::record` settles first, so a program's records are kept in the
order it made them and the record of its stop after everything before it.

A program's records go to `file_sink::FileSink` — `audit.toml`, one
`[[record]]` table per record, in the directory the program was told (its
configuration's `AuditDirectory`), else the one `XMIP_AUDIT_DIRECTORY`
names, else nowhere. The estate's tooling sets the variable to
`.local-work/audit` for everything it starts. An address's user and password
never reach a record (`redaction::without_credentials`).

## When audit cannot persist: the operating system's log

When the sink refuses a record, or there is none, `Audit` hands it to
`operating_system_log::OperatingSystemLog`, opening with the sentence that
says why. This is the fallback and not a second sink, and the rule is written
here once:

- **Windows**: the Application log, event 1000, under the source `Xmip`
  (`src/windows_event_log.rs`). Registering the source needs elevation once —
  `Install-XmipPrerequisite -Install`, elevated, does it; until then an entry
  goes under `.NET Runtime` and says so. The source's name is the ABI
  header's `XMIP_EVENT_SOURCE`. The Event Log's interface is C, called
  through `windows-sys` from that one file, the only one in this crate that
  may hold unsafe code (ADR-0050, amendment 2026-09-25;
  `test/Unsafe.Test.ps1` holds the list).
- **Linux**: one datagram to `/dev/log` (`src/syslog.rs`) — the journal's own
  socket on a systemd machine (`journalctl -t xmip`), a syslog daemon's
  elsewhere.
- **macOS**: the same datagram to `/var/run/syslog`, which the unified log
  reads.

Each is a technology under this capability in `architecture.toml`
(`file`, `syslog`, `windows-event-log`), held here rather than in a
repository of its own because the fallback is the capability's rule and a
capability does not depend on its technologies.

No test writes to the machine's log: the fallback is tested with a stand-in,
and the two tests that do write — one entry under `Xmip`, one under
`.NET Runtime` on Windows, one datagram to syslog elsewhere — are ignored by
default and run with `cargo test -- --ignored` to prove it.

`doc/architecture/observability-model.md` sections 2, 3, 5, 9 and 10 govern
it, and the record model it owns is `doc/audit-record.md` beside this file.
