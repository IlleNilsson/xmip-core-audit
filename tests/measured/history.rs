//! A history of audit records as the file sink writes them: what
//! `audit_store`'s tests and the module's timing program both read. Shared,
//! not copied: `src/audit_store.rs` takes it for its tests with `#[path]`,
//! and the includer brings the record's names into scope for it (`super`).

use std::collections::BTreeMap;
use std::path::Path;

use super::{AuditId, AuditRecord, ExecutionPhase, Origin, Severity};

/// A history of `count` records, written as the file sink writes them,
/// of a few programs on the test cluster's scopes, each of a kind and
/// a time the one before it does not decide: times rise, with records
/// written a little out of order and many sharing one moment.
pub fn history(file: &Path, count: u64) {
    let cluster = configure::fixture::test_cluster();
    let locations = [
        Some(cluster.scope()),
        Some(cluster.node_scope(0)),
        Some(cluster.node_scope(1)),
        None,
    ];
    let mut text = String::new();
    let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = |bound: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        usize::try_from(seed % bound as u64).expect("small")
    };
    let base: i128 = 1_790_000_000_000_000_000;
    for number in 0..count {
        let jitter = i128::try_from(next(3)).expect("small") * 400_000;
        let at = base + i128::from(number / 3) * 1_000_000 - jitter;
        let milliseconds = u128::try_from(at / 1_000_000).expect("after the epoch");
        let id = (milliseconds << 80) | (0x7 << 76) | u128::from(number);
        let place = next(4);
        let record = AuditRecord {
            audit_id: AuditId::new(id),
            origin: Origin {
                program: ["roll", "node", "web"][place % 3].to_string(),
                host: "edge-01".to_string(),
                process: 7,
                location: locations[place].clone(),
                hidden: place == 2 && next(9) == 0,
            },
            scope: None,
            action: ["start", "stop", "publish", "receive"][next(4)].to_string(),
            phase: ExecutionPhase::ALL[next(2)],
            severity: Severity::ALL[next(3)],
            timestamp_unix_nanos: at,
            message: Some(format!("record {}", next(1_000))),
            properties: BTreeMap::new(),
        };
        text.push_str(&record.toml());
    }
    std::fs::write(file, text).expect("written");
}
