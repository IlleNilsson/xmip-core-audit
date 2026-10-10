//! The audit log is a chain, one per writer (ADR-0070 clause 5, amended
//! 2026-10-10: *one chain per writer* — the node's, or the program's where
//! no node writes it): every record carries its number in its writer's
//! chain, the SHA-256 digest of the record before it there and its own,
//! taken over its canonical form, which holds the number and the digest
//! before it. A deleted, changed or reordered record breaks the chain where
//! it was, and [`walk`] says where, in words.
//!
//! The rule is here once. The file sink forms the chain as it appends
//! (`crate::file_sink`), Xmip Storage as it writes a node's records
//! (`xmip-core-persist`, its one writer to the runtime database); each
//! computes its records' digests over its own canonical form with
//! [`digest`] and hands the records of one writer, in the order the log
//! holds them, to [`walk`], which is what every verification calls.

use std::collections::HashMap;
use std::fmt::Write;

use codec::hex;
use sha2::{Digest as _, Sha256};

use crate::audit_entry::AuditEntry;

/// How long a digest is, in bytes.
pub const DIGEST: usize = 32;

/// A SHA-256 digest.
pub type Digest = [u8; DIGEST];

/// What the first record of a chain carries as the digest before it: none
/// was.
pub const FIRST: Digest = [0; DIGEST];

/// The SHA-256 digest of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

/// A digest as a record writes it: 64 lower-case hex digits.
#[must_use]
pub fn written(digest: &Digest) -> String {
    hex::encode(digest)
}

/// The digest 64 hex digits spell, or `None`.
#[must_use]
pub fn read(text: &str) -> Option<Digest> {
    hex::decode(text).ok()?.try_into().ok()
}

/// One record as its writer's chain holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    /// The record's identifier, as words say it.
    pub record: String,
    /// Its number in the chain, from 1.
    pub position: u64,
    /// The digest of the record before it, as it carries it.
    pub previous: Digest,
    /// Its own digest, as it carries it.
    pub digest: Digest,
    /// The digest its canonical form has now.
    pub computed: Digest,
}

/// The first place a chain breaks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Break {
    /// The record's content does not match its digest.
    Changed { record: String, position: u64 },
    /// The record is whole, and the one before it is not the one it was
    /// chained to: that one was changed, or replaced.
    Unlinked { record: String, position: u64 },
    /// Numbers `from` to `to` are not in the chain before the record.
    Deleted {
        record: String,
        position: u64,
        from: u64,
        to: u64,
    },
    /// The record stands after number `after`.
    OutOfOrder {
        record: String,
        position: u64,
        after: u64,
    },
}

/// What a walk of one writer's chain found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verdict {
    pub writer: String,
    /// How many records of the writer the walk read.
    pub records: u64,
    /// The first place the chain breaks; `None` where it is whole.
    pub broken: Option<Break>,
}

impl Verdict {
    /// Whether the chain is whole.
    #[must_use]
    pub const fn whole(&self) -> bool {
        self.broken.is_none()
    }

    /// The verdict in one sentence, opening OK or FAILED.
    #[must_use]
    pub fn said(&self) -> String {
        let writer = &self.writer;
        let mut out = String::new();
        let _ = match &self.broken {
            None => write!(
                out,
                "OK: the audit chain of {writer} is whole: {} records, each chained to the \
                 one before it.",
                self.records
            ),
            Some(Break::Changed { record, position }) => write!(
                out,
                "FAILED: the audit chain of {writer} breaks at record {record}, number \
                 {position}: it was changed, its content does not match its digest."
            ),
            Some(Break::Unlinked { record, position }) => write!(
                out,
                "FAILED: the audit chain of {writer} breaks before record {record}, number \
                 {position}: number {} is not the record it was chained to, changed or \
                 replaced.",
                position - 1
            ),
            Some(Break::Deleted {
                record,
                position,
                from,
                to,
            }) => {
                let gone = if from == to {
                    format!("number {from} is gone")
                } else {
                    format!("numbers {from} to {to} are gone")
                };
                write!(
                    out,
                    "FAILED: the audit chain of {writer} breaks before record {record}, number \
                     {position}: {gone}, deleted."
                )
            }
            Some(Break::OutOfOrder {
                record,
                position,
                after,
            }) => write!(
                out,
                "FAILED: the audit chain of {writer} breaks at record {record}, number \
                 {position}: it is out of order, found after number {after}."
            ),
        };
        out
    }
}

/// A gap the walk met, not yet known to be a deletion or a reordering.
struct Gap {
    record: String,
    position: u64,
    from: u64,
    to: u64,
}

/// Walk `writer`'s chain, its records in the order the log holds them, and
/// say the first place it breaks, or that it is whole. A gap in the
/// numbers is a deletion unless a missing number turns up later, which
/// makes it a reordering; either is reported where the gap is.
#[must_use]
pub fn walk(writer: &str, links: impl IntoIterator<Item = Link>) -> Verdict {
    let mut verdict = Verdict {
        writer: writer.to_string(),
        records: 0,
        broken: None,
    };
    let mut expected = 1;
    let mut previous = FIRST;
    let mut gap: Option<Gap> = None;
    for link in links {
        verdict.records += 1;
        if let Some(open) = &gap {
            if (open.from..=open.to).contains(&link.position) {
                verdict.broken = Some(Break::OutOfOrder {
                    record: link.record,
                    position: link.position,
                    after: open.position,
                });
                return verdict;
            }
            continue;
        }
        let broken = if link.computed != link.digest {
            Break::Changed {
                record: link.record,
                position: link.position,
            }
        } else if link.position < expected {
            Break::OutOfOrder {
                record: link.record,
                position: link.position,
                after: expected - 1,
            }
        } else if link.position > expected {
            gap = Some(Gap {
                record: link.record,
                position: link.position,
                from: expected,
                to: link.position - 1,
            });
            continue;
        } else if link.previous != previous {
            Break::Unlinked {
                record: link.record,
                position: link.position,
            }
        } else {
            expected += 1;
            previous = link.digest;
            continue;
        };
        verdict.broken = Some(broken);
        return verdict;
    }
    verdict.broken = gap.map(|gap| Break::Deleted {
        record: gap.record,
        position: gap.position,
        from: gap.from,
        to: gap.to,
    });
    verdict
}

/// The chains of `writers` in the records of one log — the file sink's,
/// read back — each walked whole, in the order the log holds its records,
/// in the order the writers are given. A record that names no writer is in
/// no chain.
#[must_use]
pub fn chains(entries: &[AuditEntry], writers: &[&str]) -> Vec<Verdict> {
    let mut links: HashMap<&str, Vec<Link>> = writers.iter().map(|w| (*w, Vec::new())).collect();
    for entry in entries {
        if let (Some(writer), Some(link)) = (entry.writer.as_deref(), entry.link())
            && let Some(chain) = links.get_mut(writer)
        {
            chain.push(link);
        }
    }
    writers
        .iter()
        .map(|writer| walk(writer, links.remove(writer).unwrap_or_default()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole chain of `count` records, each digest over its number and
    /// the one before it.
    fn chain(count: u64) -> Vec<Link> {
        let mut previous = FIRST;
        (1..=count)
            .map(|position| {
                let own = digest(&[&position.to_be_bytes()[..], &previous].concat());
                let link = Link {
                    record: format!("r{position}"),
                    position,
                    previous,
                    digest: own,
                    computed: own,
                };
                previous = own;
                link
            })
            .collect()
    }

    #[test]
    fn a_whole_chain_is_said_whole() {
        let verdict = walk("partner-x", chain(4));
        assert!(verdict.whole());
        assert_eq!(verdict.records, 4);
        assert!(verdict.said().starts_with("OK: "), "{}", verdict.said());
        assert!(walk("partner-x", Vec::new()).whole(), "an empty chain");
    }

    #[test]
    fn a_changed_record_breaks_the_chain_where_it_is() {
        let mut links = chain(4);
        links[2].computed[0] ^= 1;
        let verdict = walk("w", links);
        let changed = Break::Changed {
            record: "r3".to_string(),
            position: 3,
        };
        assert_eq!(verdict.broken, Some(changed));
        assert!(verdict.said().contains("was changed"), "{}", verdict.said());
    }

    #[test]
    fn a_record_redigested_after_a_change_breaks_the_link_after_it() {
        let mut links = chain(4);
        links[1].digest[0] ^= 1;
        links[1].computed = links[1].digest;
        let verdict = walk("w", links);
        let broken = Some(Break::Unlinked {
            record: "r3".to_string(),
            position: 3,
        });
        assert_eq!(verdict.broken, broken);
        assert!(
            verdict.said().contains("number 2 is not"),
            "{}",
            verdict.said()
        );
    }

    #[test]
    fn a_deleted_record_is_said_gone_before_the_next() {
        let mut links = chain(5);
        links.remove(1);
        let verdict = walk("w", links);
        let deleted = Break::Deleted {
            record: "r3".to_string(),
            position: 3,
            from: 2,
            to: 2,
        };
        assert_eq!(verdict.broken, Some(deleted));
        assert!(verdict.said().contains("number 2 is gone, deleted"));
    }

    #[test]
    fn a_reordered_record_is_said_out_of_order_after_the_one_it_follows() {
        let mut links = chain(5);
        links.swap(1, 2);
        let verdict = walk("w", links);
        let moved = Break::OutOfOrder {
            record: "r2".to_string(),
            position: 2,
            after: 3,
        };
        assert_eq!(verdict.broken, Some(moved));
        assert!(verdict.said().contains("found after number 3"));
    }

    #[test]
    fn a_digest_is_written_as_hex_and_read_back() {
        let own = digest(b"record");
        assert_eq!(read(&written(&own)), Some(own));
        assert_eq!(read("00"), None, "too short");
    }
}
