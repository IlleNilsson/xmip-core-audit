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
phase = "failure"
severity = "error"
message = "the snapshot is gone"
[record.properties]
"category" = "Microsoft.AspNetCore.Components.Server.Circuits.CircuitHost"
"exception" = "System.InvalidOperationException"
```

A process that belongs somewhere in Xmip writes where, after `process`:
`location = "xmip:///C1/node/R1"`, the location it declared (ADR-0053 clause
3), on every record it makes once it declared it. A program that serves no
scope writes none. A reader groups records by it — cluster, node, program —
and never by a program's name (ADR-0062, amendment 2026-09-29).

When audit cannot persist a record, the operating system's log holds it, one
line opening with why (the README beside this file says where, per platform).
That is the persistence floor of *failure records are always persisted*: a
record the sink refused is still somewhere an operator can read.
