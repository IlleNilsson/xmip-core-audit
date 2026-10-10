# xmip-core-audit

The audit record: the persistent accountability record of what Xmip did,
where, by whom, why, when and with what outcome. An `AuditRecord` carries its
origin — the program, host and process, and the location it serves, the one
home of its cluster and its node — its scope when it belongs to a Message's
execution (`execution_scope::ExecutionScope`, the artifact that acted spelled
out: its kind, name and version, no reference), its action, phase and
severity; an `AuditPolicy` decides record or suppress; an `AuditSink` persists;
`Audit` puts the three together.

Audit is cross-cutting, not a stage. A record of an act on a Message holds
that Message and its Streams' bytes, spelled out as they were, with each
Stream's SHA-256 digest so the copy is verified when read (ADR-0070): a
node's record of a Publication or a Replay, which Xmip Storage keeps with
them (`persist::storage::Audited`; `doc/audit-record.md`). A program's own
record holds none. It never becomes the execution bottleneck: an action emits an envelope
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
`ProgramAudit`. No program writes a record of its own. A record a node
writes to Xmip Storage instead, where its Publications are audited
(ADR-0062, amendment 2026-10-01), is an `AuditRecord` in its TOML form that
says it came from `ProgramAudit::origin`, so a reader groups it with the
program's own.

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

## The audit log is a chain, one per writer (ADR-0070 clause 5)

Every record carries its place in its writer's chain (amended 2026-10-10:
*one chain per writer*): the writer — `Origin::writer`, the location the
process declared where it is a node's, else the program's name — its number
there from 1, the SHA-256 digest of the record before it in that chain
(`previous`, 64 zeros for the first) and its own (`digest`). The rule is
`audit_chain`, here once: `digest` is the SHA-256 of a record's canonical
form, and `walk` takes one writer's records in the order the log holds them
and says, in one sentence opening OK or FAILED, the first place the chain
breaks — a record whose content does not match its digest (changed), one
whose number skips (deleted before it), one out of its order, or one whose
`previous` is not the digest of the record before it — or that it is whole.

**In `audit.toml`** the file sink forms the chain as it appends: holding
`audit.lock`, a file beside it, it reads where the writer's chain stands —
what was appended since this process last looked, or, for a writer it has
not met, the file read back from its end to that writer's last record, so a
program started again goes on from its last record — and appends the record
after it in one write (`file_chain`). The canonical form is the record's
`[[record]]` table exactly as written, its blank line with it, without the
one line `digest = "…"`; `writer`, `position` and `previous` stand after
`audit_id`, and `digest` after them. **In Xmip Storage** a node's records
are chained by the audit keeper as it keeps them, over a canonical form of
its own that holds the record's row and its Streams' records
(`persist::storage::chain_digest`); the walk is this one.

Asked `verify` (`yes`), `AuditQuery` walks the chain of each writer of the
records it matched over every record in the file, a hidden run's among
them, read from the file's bytes as they are now (`audit_store::read_whole`);
the page's `chains` carry each verdict. `xmip-cli audit --verify`,
`Get-XmipAudit -Verify` and the Audit view's *verify chains* are that query.

## Whose a record is, and reading it back (ADR-0062, amendment 2026-09-29)

A process that belongs somewhere in Xmip says where: `ProgramAudit::locate`
takes the location it declares (ADR-0053 clause 3) — `xmip:///C1` for a
Playground roll or its cluster, `xmip:///C1/node/R1` for a node or the Xmip
Service — and every record from then on, by any clone and the panic hook's,
carries it as `location`. A program that serves no scope — a cmdlet, the web
host, the command line — declares none, and a reader shows its records under
their host. Nothing reads meaning out of a program's name.

The one reader of the file is here too. `audit_store::read` reads
`audit.toml` into `audit_entry::AuditEntry` records, keeps them, and reads
only what was appended since the last time — a table is read once it ends
with its blank line, so a record still being appended waits for the next
read — and a file that got shorter is read again from its start.
`audit_query::AuditQuery` is what every surface asks of them, in the same
words: who (`location`, at and beneath a scope; `host`, the records that
declared none; `program`; `record`, one of them), the scope `pattern` —
`observe::wildcard`, the estate's one wildcard, over each location, a record
with none standing at the root — `severity`, `action`, `from` and `to`,
`sort` by any `audit_column::Column` either way, and a bounded page
(`offset`, `limit`, at most 1,000). Its answer counts what matched, gives
the page, the groups one step down the drill — clusters and hosts, a
cluster's nodes and its own programs, a node's programs — and the actions
there are to choose from. The runtime forwards it as `xmip_audit_read_v1`
(`xmip_operate.h` section 9), `Xmip.Surface`'s `ProgramAudit.Read` calls
that, and the Audit view, `xmip-cli audit` and `Get-XmipAudit` are that call.

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
