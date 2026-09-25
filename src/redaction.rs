//! What a record never carries: the user and password an address may hold.
//!
//! An operator may type a web host as `https://ops:secret@edge-01:5087`, and
//! a program records what it was told. The rule that the secret stays out is
//! written here, once, and applied to every program's record
//! ([`crate::program_audit::ProgramAudit`]), so no surface has to remember
//! it (ADR-0062).

/// `text` with the user information of every `scheme://user:password@host`
/// address in it left out: `https://edge-01:5087`.
#[must_use]
pub fn without_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = rest.find("://") {
        let (before, after) = rest.split_at(at + 3);
        out.push_str(before);

        // The authority runs to the path, the query, the fragment or the end
        // of the word; a user part is everything to its last `@`.
        let end = after
            .find(|character: char| "/?#".contains(character) || character.is_whitespace())
            .unwrap_or(after.len());
        let authority = &after[..end];
        let host = authority
            .rfind('@')
            .map_or(authority, |user| &authority[user + 1..]);

        out.push_str(host);
        rest = &after[end..];
    }

    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_and_password_leave_and_the_host_stays() {
        assert_eq!(
            without_credentials("https://ops:s3cr@t@edge-01:5087/hub?x=1"),
            "https://edge-01:5087/hub?x=1"
        );
        assert_eq!(
            without_credentials("remote http://ops@lab and ftp://a:b@c/d"),
            "remote http://lab and ftp://c/d"
        );
    }

    #[test]
    fn text_without_an_address_is_left_as_it_is() {
        for text in [
            "",
            "no address here",
            "mail ops@edge-01",
            "http://edge-01:5087",
        ] {
            assert_eq!(without_credentials(text), text);
        }
    }
}
