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
//!
//! The inbox is bounded: it holds at most [`INBOX`] hand-overs waiting. When
//! it is full, the one handing over waits for room — the keeper is behind
//! the disk, and that is load, not Xmip — and nothing is dropped: an audit
//! record is evidence, every program's records are kept (ADR-0062: *nothing
//! an Xmip program does fails silently*), and a writer's chain proves its
//! log complete (ADR-0070 clause 5), which a record left out would break
//! in silence. Refusing the record instead would hand the caller a record
//! with nowhere to go but the operating system's log, which is for when
//! audit cannot persist (ADR-0062 clause 3), not for when it is busy. The
//! keeper's own thread never waits for itself: what a record being kept
//! hands over is queued past the bound, and is bounded by that record. A
//! job that panics is kept from ending the keeper, so one waiting for room
//! is never left waiting for a thread that is gone.

use std::cell::Cell;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::thread;

/// One record, or several, to keep.
type Job = Box<dyn FnOnce() + Send>;

/// The most hand-overs the inbox holds waiting before the next one waits
/// for room.
pub const INBOX: usize = 4_096;

thread_local! {
    /// True on the keeper's own thread, which never waits for itself.
    static KEEPING: Cell<bool> = const { Cell::new(false) };
}

/// The hand-overs waiting, and the two waits on them.
struct Inbox {
    waiting: Mutex<VecDeque<Job>>,
    /// Signalled when a job is handed over.
    handed: Condvar,
    /// Signalled when the keeper took one, so there is room.
    taken: Condvar,
}

impl Inbox {
    fn hand(&self, job: Job) {
        let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        if !KEEPING.get() {
            while waiting.len() >= INBOX {
                waiting = self
                    .taken
                    .wait(waiting)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
        waiting.push_back(job);
        drop(waiting);
        self.handed.notify_one();
    }

    fn keep(&self) -> ! {
        KEEPING.set(true);
        loop {
            let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
            let job = loop {
                match waiting.pop_front() {
                    Some(job) => break job,
                    None => {
                        waiting = self
                            .handed
                            .wait(waiting)
                            .unwrap_or_else(PoisonError::into_inner);
                    }
                }
            };
            drop(waiting);
            self.taken.notify_all();
            // A record that panicked is not kept; the keeper goes on to the
            // next, and the panic hook has said what happened.
            let _ = catch_unwind(AssertUnwindSafe(job));
        }
    }

    /// How many hand-overs wait.
    fn waiting(&self) -> usize {
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The keeper's inbox, started the first time a record is handed over;
/// `None` where the operating system would not start it.
fn inbox() -> Option<&'static Inbox> {
    static INBOX_KEPT: OnceLock<Option<&'static Inbox>> = OnceLock::new();
    *INBOX_KEPT.get_or_init(|| {
        let inbox: &'static Inbox = Box::leak(Box::new(Inbox {
            waiting: Mutex::new(VecDeque::new()),
            handed: Condvar::new(),
            taken: Condvar::new(),
        }));
        thread::Builder::new()
            .name("xmip-audit-keeper".to_string())
            .spawn(move || inbox.keep())
            .ok()
            .map(|_| inbox)
    })
}

/// Keep `job` on the keeper's thread, in order after everything handed over
/// before it; here, now, when there is no keeper. Waits for room while the
/// inbox holds [`INBOX`] hand-overs.
pub fn later(job: impl FnOnce() + Send + 'static) {
    let job: Job = Box::new(job);
    match inbox() {
        Some(inbox) => inbox.hand(job),
        None => job(),
    }
}

/// How many hand-overs wait in the inbox now.
#[must_use]
pub fn waiting() -> usize {
    inbox().map_or(0, Inbox::waiting)
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// The tests that hold the keeper, or time it, one at a time: the keeper
    /// is the process's one.
    static SERIAL: Mutex<()> = Mutex::new(());

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
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
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

    #[test]
    fn settling_on_the_keeper_returns_at_once() {
        let (done, finished) = mpsc::channel();
        later(move || {
            settle();
            let _ = done.send(());
        });
        finished.recv().expect("the keeper did not wait for itself");
    }

    #[test]
    fn a_full_inbox_makes_the_writer_wait_and_loses_nothing() {
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let (release, held) = mpsc::channel::<()>();
        let kept = Arc::new(AtomicUsize::new(0));
        later(move || {
            let _ = held.recv();
        });
        let more = INBOX * 2;
        let writer = {
            let kept = Arc::clone(&kept);
            thread::spawn(move || {
                for _ in 0..more {
                    let kept = Arc::clone(&kept);
                    later(move || {
                        kept.fetch_add(1, Ordering::Relaxed);
                    });
                }
            })
        };
        let started = Instant::now();
        while waiting() < INBOX && started.elapsed() < Duration::from_secs(5) {
            thread::yield_now();
        }
        assert!(waiting() <= INBOX, "{} wait, over the bound", waiting());
        assert!(!writer.is_finished(), "the writer waits for room");

        release.send(()).expect("the keeper holds the receiver");
        writer.join().expect("the writer went on");
        settle();
        assert_eq!(kept.load(Ordering::Relaxed), more, "every record kept");
    }

    #[test]
    fn a_job_that_panics_does_not_end_the_keeper() {
        later(|| panic!("a record that could not be kept"));
        let (done, finished) = mpsc::channel();
        later(move || {
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(5))
            .expect("the keeper went on");
    }
}
