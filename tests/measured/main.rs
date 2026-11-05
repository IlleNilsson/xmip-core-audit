//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): the audit keeper and the audit reader held to a time. A plain
//! `cargo test` leaves it out; the landing runs it after every other test
//! of the module, alone, one test at a time (`cargo test --test measured
//! --all-features -- --test-threads=1`), so what is measured is Xmip's work
//! and not its neighbors':
//!
//! - handing a record over never waits for its keeping;
//! - a page takes as long whatever the history behind it, over the
//!   history `audit_store`'s tests read (`history.rs`, shared).

mod history;

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use history::history;
use xcore::{AuditId, ExecutionPhase, Severity};
use xmip_core_audit::audit_query::AuditQuery;
use xmip_core_audit::audit_record::AuditRecord;
use xmip_core_audit::audit_store::{BUDGET, ask, held};
use xmip_core_audit::keeper::{later, settle};
use xmip_core_audit::origin::Origin;

#[test]
fn handing_over_does_not_wait_for_the_keeping() {
    let (release, held) = mpsc::channel::<()>();
    later(move || {
        let _ = held.recv();
    });
    // The keeper is blocked on the first job; handing over still returns.
    let started = Instant::now();
    for _ in 0..1_000 {
        later(|| {});
    }
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a thousand hand-overs took {:?}",
        started.elapsed()
    );
    release.send(()).expect("the keeper holds the receiver");
    settle();
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("xmip-audit-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("made");
    directory
}

fn query(pairs: &[(&str, &str)]) -> AuditQuery {
    AuditQuery::from_pairs(pairs.iter().copied()).expect("a query")
}

/// The median of `runs` asks of `asked`.
fn timed(file: &Path, asked: &AuditQuery, runs: usize) -> Duration {
    let mut took: Vec<Duration> = (0..runs)
        .map(|_| {
            let started = Instant::now();
            let _ = ask(file, asked).expect("asked");
            started.elapsed()
        })
        .collect();
    took.sort();
    took[runs / 2]
}

#[test]
fn a_page_takes_as_long_whatever_the_history_behind_it() {
    let directory = scratch("time");
    let (short, long) = (directory.join("short.xmip"), directory.join("long.xmip"));
    history(&short, 2_048);
    history(&long, 40_960);
    let pages = [
        query(&[("limit", "200")]),
        query(&[("offset", "1000"), ("limit", "200")]),
        query(&[("severity", "Error"), ("sort", "program"), ("limit", "200")]),
    ];
    for asked in &pages {
        ask(&short, asked).expect("indexed once");
        ask(&long, asked).expect("indexed once");
        let (shorter, longer) = (timed(&short, asked, 9), timed(&long, asked, 9));
        println!("{asked:?}: {shorter:?} over 2,048 records, {longer:?} over 40,960");
        assert!(
            longer <= shorter * 3 + Duration::from_millis(2),
            "{longer:?} over 40,960 records against {shorter:?} over 2,048"
        );
    }
    println!("the indexes of 43,008 records hold {} bytes", held());
    assert!(held() <= BUDGET);
    let _ = std::fs::remove_dir_all(&directory);
}
