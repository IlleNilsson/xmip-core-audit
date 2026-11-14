//! A record kept by the file sink — appended in its writer's chain and on
//! the disk before it is said written (ADR-0062, amendment 2026-11-13) —
//! held to the millisecond rule beside the disk's own durable write: as
//! many bytes appended to a file of the same directory, opened, flushed and
//! closed, round by round under the same load.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use xcore::fastest::FIVE;
use xcore::latency::spread;
use xcore::{AuditId, ExecutionPhase, Severity};
use xmip_core_audit::AuditSink;
use xmip_core_audit::audit_record::AuditRecord;
use xmip_core_audit::file_sink::FileSink;
use xmip_core_audit::origin::Origin;

use super::scratch;

/// How many records are measured.
const ROUNDS: usize = 8 * FIVE;

/// The bound: a millisecond.
const BOUND: Duration = Duration::from_millis(1);

/// A record as an act's is: who asked, what and what came of it.
fn record(number: usize) -> AuditRecord {
    AuditRecord {
        audit_id: AuditId::new(u128::try_from(number).unwrap_or_default()),
        origin: Origin::here("audit timing"),
        scope: None,
        action: "act".to_string(),
        phase: ExecutionPhase::Finished,
        severity: Severity::Information,
        timestamp_unix_nanos: 0,
        message: Some("CN=alice asked to pause subscription 'Orders': taken".to_string()),
        properties: BTreeMap::from([
            ("act".to_string(), "pause".to_string()),
            ("outcome".to_string(), "taken".to_string()),
        ]),
    }
}

/// The disk's own durable write of `bytes` bytes to `beside`: opened,
/// appended, flushed and closed.
fn durable(beside: &Path, bytes: usize) -> Duration {
    let text = vec![b'#'; bytes];
    let began = Instant::now();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(beside)
        .expect("opened");
    file.write_all(&text).expect("written");
    file.sync_data().expect("flushed");
    drop(file);
    began.elapsed()
}

#[test]
fn a_record_is_on_the_disk_within_a_millisecond_of_the_disks_own_durable_write() {
    let directory = scratch("written");
    let sink = FileSink::new(&directory);
    // A process's first record reads the file once, to find its chain.
    sink.write(&record(0)).expect("written");
    let beside = directory.join("beside.toml");
    let (mut kept, mut own) = (Vec::new(), Vec::new());
    for number in 1..=ROUNDS {
        let before = fs::metadata(sink.path()).expect("there").len();
        let began = Instant::now();
        sink.write(&record(number)).expect("written");
        kept.push(began.elapsed());
        let grew = fs::metadata(sink.path()).expect("there").len() - before;
        own.push(durable(&beside, usize::try_from(grew).unwrap_or_default()));
    }
    let kept = spread("a record kept by the file sink", kept).fastest_of_five;
    let own = spread("the disk's own durable write of as many bytes", own).fastest_of_five;
    assert!(
        kept < own + BOUND,
        "a record took {kept:?}, the disk's own durable write {own:?}"
    );
    let _ = fs::remove_dir_all(&directory);
}
