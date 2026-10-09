# The audit record

Moved here from the estate root on 2026-09-12 (ADR-0020 clause 3: the document lives where its subject lives).

Every architectural action is auditable and audit is available throughout the
execution chain (`doc/architecture/observability-model.md`, section 2). This
document is the record model that capability owns.

### Lifecycle

Every audited action follows one of two shapes:

```text
Begin -> Execute -> Finished
Begin -> Execute -> Failure
```

`Finished` and `Failure` are mutually exclusive for one execution attempt.

### Severity, which is independent of phase

```text
Information   normal execution and successful completion
Warning       recoverable, degraded or exceptional; execution may continue
Error         failure, or a condition preventing continuation
```

```text
Transform / Begin   / Information
Transform / Execute / Information
Transform / Finished/ Information

Send      / Begin   / Information
Send      / Execute / Warning
Send      / Finished/ Warning

Process   / Begin   / Information
Process   / Execute / Error
Process   / Failure / Error
```

### Policy

Every action is auditable; effective policy decides what is *recorded*.

```text
Xmip -> Cluster -> Node -> Artifact type -> Artifact -> Action -> Phase -> Severity
```

**The most specific configured policy wins; unspecified settings inherit from
the containing level.** Policy may set enabled or disabled, phase, severity,
action type, artifact type, individual artifact, node, cluster, detail level,
and sampling or throttling for high-volume Information records.

That range is the point: detailed Path-execution auditing on one development
artifact, and Error-only auditing on a high-volume production artifact, from one
model.

**Failures are always audited, and failure audit records are always persisted.**
That is not policy-configurable.

### The persistent audit directive

Configured on a Definition — typically a Receive Location:

> Audit this Receive Location, and every Message and every generation descended
> from it.

When active, audit intent is carried as **runtime metadata on the Message
itself** and applies through receive, accept, assignment, transformation,
process execution, subscription, pass-on, pickup, send, retry, failure and
leaving Xmip.

It is persistent runtime metadata. It is not a log setting, not a UI filter and
not a diagnostic flag — those all evaporate at the wrong moment, which is why
this is none of them.

Mandatory audit remains regardless. The directive adds depth to configured
flows; it cannot remove the floor.

## Performance

**Audit must not become the execution bottleneck.** Normal execution emits a
small audit envelope onto a bounded asynchronous channel; `xmip-core-audit`
batches and persists independently of the action that produced it.

When capacity is exhausted, configured policy decides whether Xmip discards
selected Information records, reduces detail, throttles or samples, blocks the
audited action, or fails it.

Warning and Error records normally require stronger delivery guarantees than
Information. Some conditions are configurable as **non-suppressible**: audit
subsystem failure, security-critical failure, configuration corruption, and
persistence failure that risks losing required evidence.

All of this is [decided, not built](../../../../../doc/architecture/estate-map.md#bounded-audit-channel). What runs
is `keeper`, an unbounded queue on one thread that Event delivery records
are handed to, and `ProgramAudit::record`, which waits for that queue to
drain and then appends the record to `audit.toml` before it returns
([built, in the assembled service](../../../../../doc/architecture/estate-map.md#program-audit)).


## A program's record

Every Xmip program audits, not only the runtime (ADR-0062). A program's own
act — a host that started, a command an operator ran, a cmdlet that failed —
belongs to no Message's execution, so its record carries no scope; it carries
its **origin** instead: the program's name, the host and the process, which
is what outlives the process (observability-model section 3). A program's
records are all kept: its acts are few and each one matters.

On disk a record is one TOML table, appended:

```toml
[[record]]
audit_id = "01a0d72a-3f6f-7613-9a1b-1824ccbedc90"
at = "2026-09-25T06:04:25.327773900Z"
program = "xmip-gui-web"
host = "edge-01"
process = "39800"
action = "error logged"
phase = "Failure"
severity = "Error"
message = "the snapshot is gone"
[record.properties]
"category" = "Microsoft.AspNetCore.Components.Server.Circuits.CircuitHost"
"exception" = "System.InvalidOperationException"
```

A phase and a severity are written as their words as `xcore::ExecutionPhase`
and `xcore::Severity` name them — `Begin`, `Execute`, `Finished`, `Failure`;
`Information`, `Warning`, `Error` — the one word list every reader, query
and surface takes (2026-10-09).

A process that belongs somewhere in Xmip writes where, after `process`:
`location = "xmip:///<cluster>/node/<node>"`, the location it declared (ADR-0053 clause
3), on every record it makes once it declared it. A program that serves no
scope writes none. A reader groups records by it — cluster, node, program —
and never by a program's name (ADR-0062, amendment 2026-09-29).

A process of a run that declared itself hidden writes `hidden = "true"`
after its location, on every record from the moment it declared
(`ProgramAudit::hide`), and nothing else writes the key. A reader leaves such
records out unless its query includes them — `hidden = "include"` in the
query's words — by the one rule, `observe::run::shown` (ADR-0028, amendment
2026-09-30).

When audit cannot persist a record, the operating system's log holds it, one
line opening with why (the README beside this file says where, per platform).
That is the persistence floor of *failure records are always persisted*: a
record the sink refused is still somewhere an operator can read.

## A record of an act on a Message

An audit record of an act on a Message carries that Message in full, as it
was at the audited event, and its Stream's bytes with their SHA-256 digest
and length, so an auditor reads the untarnished data and the copy is verified
when it is read (ADR-0070, clauses 1, 2 as amended and 4). A node writes such
a record through Xmip Storage, not to a file: a Publication's and a Replay's.
Its body is the `[[record]]` table above; beside it travel the Message in its
one binary form and the Stream it is over (`persist::storage::Audited`). The
audit keeper keeps the Stream's bytes beside the kept record, a chunk at a
time, and the digest and length in its `stream_digest` and `stream_length`
columns, taken from the Stream's own record, where the writer took the digest
as the bytes passed once. A read of the copy that does not match its digest
or its length is refused in words (`persist::storage::ChunkReader::audited`).
