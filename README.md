# xmip-core-audit

The audit record: the persistent accountability record of what Xmip did,
where, by whom, why, when and with what outcome. An `AuditRecord` carries its
scope, action, phase and severity; an `AuditPolicy` decides record or
suppress; an `AuditSink` persists.

Audit is cross-cutting, not a stage, and it holds no payloads — retention
does. It never becomes the execution bottleneck: an action emits an envelope
and this crate persists independently of it. Failures are always audited and
failure records are always persisted; that is not policy.

`doc/architecture/observability-model.md` sections 2, 3, 5, 9 and 10 govern
it, and the record model it owns is `doc/audit-record.md` beside this file.
Each sink is a technology under this repository; `architecture.toml` names
them.
