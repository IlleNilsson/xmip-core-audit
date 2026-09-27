//! The keeper: one thread in the process that keeps records in the order
//! they were handed to it, so recording never makes the caller wait for a
//! disk.
//!
//! What Xmip does around a payload is measured in milliseconds (the owner,
//! 2026-09-26), and one audit record is a file append that can take
//! milliseconds. So a record made on a path that must not wait — an Event's
//! delivery, a subscription closed — is handed to the keeper with [`later`]
//! and the caller goes on. [`settle`] waits until everything handed over
//! before it is kept, and a direct [`crate::program_audit::ProgramAudit::record`]
//! settles first: a program's records are kept in the order it made them, and
//! the record of its stop is kept after everything it handed over before.

use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Sender};
use std::thread;

/// One record, or several, to keep.
type Job = Box<dyn FnOnce() + Send>;

thread_local! {
    /// True on the keeper's own thread, which never waits for itself.
    static KEEPING: Cell<bool> = const { Cell::new(false) };
}

/// The keeper's inbox, started the first time a record is handed over;
/// `None` where the operating system would not start it.
fn inbox() -> Option<&'static Sender<Job>> {
    static INBOX: OnceLock<Option<Sender<Job>>> = OnceLock::new();
    INBOX
        .get_or_init(|| {
            let (sender, receiver) = mpsc::channel::<Job>();
            thread::Builder::new()
                .name("xmip-audit-keeper".to_string())
                .spawn(move || {
                    KEEPING.set(true);
                    for job in receiver {
                        job();
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

/// Keep `job` on the keeper's thread, in order after everything handed over
/// before it; here, now, when there is no keeper.
pub fn later(job: impl FnOnce() + Send + 'static) {
    let job: Job = Box::new(job);
    match inbox() {
        Some(inbox) => {
            if let Err(returned) = inbox.send(job) {
                (returned.0)();
            }
        }
        None => job(),
    }
}

/// Wait until every record handed over before this call is kept. Returns at
/// once on the keeper's own thread, where everything before is already kept.
pub fn settle() {
    if KEEPING.get() {
        return;
    }
    let (done, finished) = mpsc::channel();
    later(move || {
        let _ = done.send(());
    });
    // A keeper that died has kept what it could; nothing is left to wait for.
    let _ = finished.recv();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn records_are_kept_in_the_order_handed_over_and_settle_waits_for_them() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        for number in 0..100 {
            let kept = Arc::clone(&kept);
            later(move || kept.lock().expect("no poison").push(number));
        }
        settle();
        let kept = kept.lock().expect("no poison");
        assert_eq!(*kept, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn handing_over_does_not_wait_for_the_keeping() {
        let (release, held) = mpsc::channel::<()>();
        later(move || {
            let _ = held.recv();
        });
        // The keeper is blocked on the first job; handing over still returns.
        let started = std::time::Instant::now();
        for _ in 0..1_000 {
            later(|| {});
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "a thousand hand-overs took {:?}",
            started.elapsed()
        );
        release.send(()).expect("the keeper holds the receiver");
        settle();
    }

    #[test]
    fn settling_on_the_keeper_returns_at_once() {
        let (done, finished) = mpsc::channel();
        later(move || {
            settle();
            let _ = done.send(());
        });
        finished.recv().expect("the keeper did not wait for itself");
    }
}
