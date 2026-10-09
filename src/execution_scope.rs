//! What a Message's audited action ran in: the execution, the Journey, the
//! Message and the artifact that acted, each spelled out as an audit record
//! keeps it (the owner, 2026-10-09: *In an Audit you can't have references,
//! it should be spelled out*). Where it ran — the cluster and the node — is
//! the record's origin, its location, and nowhere else.

use xcore::{ExecutionId, JourneyId, MessageId};

/// The artifact an action ran as: what it is, its name and its version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRef {
    pub artifact_type: &'static str,
    pub name: String,
    pub version: Option<String>,
}

/// A Message's action as its audit record carries it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionScope {
    pub execution_id: ExecutionId,
    pub journey_id: JourneyId,
    pub message_id: MessageId,
    pub artifact: ArtifactRef,
}
