//! What a Message's audited action ran in: the execution, the Journey, the
//! Message, the artifact that acted, and where.

use xcore::{ArtifactId, ClusterId, ExecutionId, JourneyId, MessageId, NodeId};

/// The artifact an action ran as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRef {
    pub artifact_id: ArtifactId,
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
    pub node_id: Option<NodeId>,
    pub cluster_id: Option<ClusterId>,
}
