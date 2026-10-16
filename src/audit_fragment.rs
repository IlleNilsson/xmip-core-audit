//! What the audit file holds that is not a whole record: the bytes a write
//! left unfinished. Every table the file sink appends ends with a blank
//! line, so a file that does not end with one ends in a table whose write
//! was interrupted, or is still going on.
//!
//! The next append does not write onto it: holding the lock, the file sink
//! keeps those bytes as they were written and ends them with [`SEAL`] and a
//! blank line, so they stand apart as a fragment of their own, in no audit
//! chain, and the record after them is whole (ADR-0070 clause 5). A reader
//! reads a sealed fragment as a [`Fragment`], never as a record, and a
//! verification says each one in words, apart from whether the chains are
//! whole: nothing that was written is passed over in silence, and nothing
//! is truncated or deleted.

/// What ends two tables apart: the blank line every table ends with.
pub const BOUNDARY: &[u8] = b"\n\n";

/// The line the file sink ends an unfinished table with: a TOML comment, so
/// the file stays a TOML document wherever the unfinished bytes allow it.
pub const SEAL: &str = "# unfinished: the write of the lines above was interrupted; \
                        they are kept as written and are in no audit chain";

/// Bytes of the file that are not a whole record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    /// Where it starts, in bytes from the start of what was read.
    pub offset: usize,
    /// How many bytes it is, its seal included.
    pub length: usize,
    /// Whether it was sealed: `false` for what follows the file's last
    /// blank line, a record still being written or one interrupted that
    /// no append has sealed yet.
    pub sealed: bool,
}

impl Fragment {
    /// The fragment in one sentence: FAILED for a sealed one, a write that
    /// was interrupted; UNFINISHED for the file's unfinished end.
    #[must_use]
    pub fn said(&self) -> String {
        let (offset, length) = (self.offset, self.length);
        if self.sealed {
            format!(
                "FAILED: the {length} bytes from byte {offset} are a record whose write was \
                 interrupted; they are kept as written, sealed, and are in no audit chain."
            )
        } else {
            format!(
                "UNFINISHED: the last {length} bytes, from byte {offset}, are a record not \
                 finished: still being written, or interrupted and to be sealed by the next \
                 append."
            )
        }
    }
}

/// What to append to a file ending in `end` (its last two bytes, or fewer
/// where it is shorter) before a record, so the record is not written onto
/// an unfinished table: nothing where the file is empty or ends at a
/// [`BOUNDARY`], else the end of the unfinished line, [`SEAL`] and a blank
/// line.
#[must_use]
pub fn sealing(end: &[u8]) -> Option<String> {
    if end.is_empty() || end.ends_with(BOUNDARY) {
        return None;
    }
    let line = if end.ends_with(b"\n") { "" } else { "\n" };
    Some(format!("{line}{SEAL}\n\n"))
}

/// Whether `table`, read up to and with its blank line, is a sealed
/// fragment: its last line is [`SEAL`].
#[must_use]
pub fn sealed(table: &str) -> bool {
    table.trim_end_matches('\n').rsplit('\n').next() == Some(SEAL)
}

/// Where the whole tables of `bytes` end: after its last [`BOUNDARY`], or
/// `None` where it holds none. What follows is a table still being written.
#[must_use]
pub fn whole(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(BOUNDARY.len())
        .rposition(|pair| pair == BOUNDARY)
        .map(|at| at + BOUNDARY.len())
}

/// The tables in `bytes`, each up to and with the [`BOUNDARY`] that ends
/// it; the last one without it where `bytes` does not end at one.
pub fn tables(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = bytes;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let end = rest
            .windows(BOUNDARY.len())
            .position(|pair| pair == BOUNDARY)
            .map_or(rest.len(), |at| at + BOUNDARY.len());
        let (table, after) = rest.split_at(end);
        rest = after;
        Some(table)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_at_a_boundary_needs_no_seal_and_an_unfinished_one_is_sealed() {
        assert_eq!(sealing(b""), None, "an empty file");
        assert_eq!(sealing(b"\n\n"), None, "a whole table ends it");

        let cut = sealing(b"fo").expect("cut inside a line");
        assert_eq!(cut, format!("\n{SEAL}\n\n"));
        let at_line = sealing(b"\"\n").expect("cut at the end of a line");
        assert_eq!(at_line, format!("{SEAL}\n\n"));

        assert!(sealed(&format!("[[record]]\naction = \"fo{cut}")));
        assert!(!sealed("[[record]]\naction = \"four\"\n\n"));
    }

    #[test]
    fn tables_end_at_each_blank_line_and_the_last_may_be_unfinished() {
        let found: Vec<&[u8]> = tables(b"a\n\nb\nc\n\nd").collect();
        assert_eq!(found, [&b"a\n\n"[..], b"b\nc\n\n", b"d"]);
    }

    #[test]
    fn each_fragment_is_said_in_words() {
        let sealed = Fragment {
            offset: 10,
            length: 20,
            sealed: true,
        };
        assert!(
            sealed
                .said()
                .starts_with("FAILED: the 20 bytes from byte 10")
        );
        let open = Fragment {
            sealed: false,
            ..sealed
        };
        assert!(open.said().starts_with("UNFINISHED: "), "{}", open.said());
    }
}
