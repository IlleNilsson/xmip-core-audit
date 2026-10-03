//! What a reader asks of the audit store, and the page it gets back
//! (ADR-0062, amendment 2026-09-29): which records — by who, by the scope
//! pattern every surface filters with, by severity, action and time — in
//! what order, and which page of them; with the groups one step down the
//! drill and the actions there are to choose from.
//!
//! Every surface asks in the same words ([`AuditQuery::from_pairs`]), so
//! the command line, PowerShell and the views cannot read a filter three
//! ways. Who a record is, is what its process declared ([`AuditEntry`]'s
//! location), and a record with none is its host's: nothing is read out of a
//! program's name (the estate's rule, capability not name).

use std::collections::{BTreeMap, BTreeSet};

use codec::civil::read_rfc3339;
use observe::Scope;
use observe::run::shown;
use observe::wildcard::matches;

use crate::audit_column::{Column, SEVERITIES};
use crate::audit_entry::AuditEntry;

/// The most records one page carries.
pub const MOST: usize = 1_000;

/// A page's length when the reader states none.
pub const PAGE: usize = 100;

/// One reader's question.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditQuery {
    /// The scope pattern, `*` and `?`, over each record's location; a record
    /// with none is at the root, which only `*` names.
    pub pattern: Option<String>,
    /// Records whose process declared this scope or one beneath it.
    pub location: Option<String>,
    /// Records whose process declared no location, on this host.
    pub host: Option<String>,
    /// Records of this program, exactly.
    pub program: Option<String>,
    /// The one record with this identifier; every other filter is set aside.
    pub record: Option<String>,
    pub severity: Option<String>,
    pub action: Option<String>,
    /// At or after, nanoseconds since the epoch.
    pub from: Option<i128>,
    /// At or before, nanoseconds since the epoch.
    pub to: Option<i128>,
    pub sort: Column,
    /// Newest, or the greatest, first. A query that states no order has it.
    pub descending: bool,
    pub offset: usize,
    pub limit: usize,
    /// Whether the records of a run that declared itself hidden are read
    /// too; left out unless asked (ADR-0028, amendment 2026-09-30), by the
    /// one rule, [`observe::run::shown`].
    pub including_hidden: bool,
}

/// The words the `hidden` key takes: leave what is hidden out, the default,
/// or include it.
pub const HIDDEN: [&str; 2] = ["exclude", "include"];

/// A group one step down the drill from where a query stands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditGroup {
    /// `cluster`, `node`, `scope`, `program` or `host`.
    pub kind: &'static str,
    /// What the group is: a scope, a program's name or a host's.
    pub who: String,
    pub count: usize,
    pub warnings: usize,
    pub errors: usize,
    /// The newest record's time, as written.
    pub latest: String,
    /// Some record in the group came from a hidden run: a reader that
    /// included what is hidden marks the group as test.
    pub hidden: bool,
}

/// What a query found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditPage {
    /// How many records the store holds.
    pub read: usize,
    /// How many matched, of which `records` is the page asked for.
    pub matched: usize,
    pub records: Vec<AuditEntry>,
    pub groups: Vec<AuditGroup>,
    /// Every action where the query stands, whatever its action filter says:
    /// what a reader offers to choose from.
    pub actions: Vec<String>,
}

impl AuditQuery {
    /// A query in the words every surface uses, key then value: `pattern`,
    /// `location`, `host`, `program`, `record`, `severity` (a severity's
    /// word), `action`, `from` and `to` (RFC 3339, or a date and a time with
    /// no zone, read as UTC), `sort` (a [`Column`]'s word), `order`
    /// (`ascending` or `descending`), `offset` and `limit` (at most
    /// [`MOST`]), and `hidden` ([`HIDDEN`]: `include` reads the records of
    /// a run that declared itself hidden too). An empty value is no filter.
    ///
    /// # Errors
    /// A key that is none of these, or a value its key does not take, as
    /// one sentence opening REFUSED.
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, String> {
        let mut query = Self {
            descending: true,
            limit: PAGE,
            ..Self::default()
        };

        for (key, value) in pairs {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let text = Some(value.to_string());
            match key {
                "pattern" => query.pattern = text,
                "location" => query.location = text,
                "host" => query.host = text,
                "program" => query.program = text,
                "record" => query.record = text,
                "action" => query.action = text,
                "severity" => query.severity = Some(word(key, value, &SEVERITIES)?),
                "from" => query.from = Some(moment(key, value)?),
                "to" => query.to = Some(moment(key, value)?),
                "sort" => {
                    query.sort = Column::named(value)
                        .ok_or_else(|| refusal(key, value, &Column::words()))?;
                }
                "order" => {
                    query.descending =
                        word(key, value, &["ascending", "descending"])? == "descending";
                }
                "offset" => query.offset = number(key, value)?,
                "limit" => query.limit = number(key, value)?.min(MOST),
                "hidden" => query.including_hidden = word(key, value, &HIDDEN)? == "include",
                other => {
                    return Err(format!(
                        "REFUSED: an audit read takes pattern, location, host, program, record, \
                         severity, action, from, to, sort, order, offset, limit and hidden, \
                         not {other:?}."
                    ));
                }
            }
        }

        Ok(query)
    }

    /// Ask `entries`. What a hidden run recorded is not there for a query
    /// that did not include it: not counted, not grouped, not found by its
    /// identifier.
    #[must_use]
    pub fn ask(&self, entries: &[AuditEntry]) -> AuditPage {
        let entries: Vec<&AuditEntry> = entries
            .iter()
            .filter(|entry| shown(entry.hidden, self.including_hidden))
            .collect();

        if let Some(record) = &self.record {
            let records: Vec<AuditEntry> = entries
                .iter()
                .filter(|entry| &entry.audit_id == record)
                .take(1)
                .map(|entry| (*entry).clone())
                .collect();
            return AuditPage {
                read: entries.len(),
                matched: records.len(),
                records,
                ..AuditPage::default()
            };
        }

        let standing: Vec<&AuditEntry> = entries
            .iter()
            .copied()
            .filter(|entry| self.who(entry) && self.narrowed(entry))
            .collect();
        let actions: BTreeSet<&str> = standing.iter().map(|entry| entry.action.as_str()).collect();
        let mut matched: Vec<&AuditEntry> = standing
            .into_iter()
            .filter(|entry| {
                self.action
                    .as_deref()
                    .is_none_or(|action| entry.action == action)
            })
            .collect();
        let groups = if self.program.is_some() {
            Vec::new()
        } else {
            self.groups(&matched)
        };

        matched.sort_by(|left, right| {
            let order = self
                .sort
                .compare(left, right)
                .then(left.at_nanos.cmp(&right.at_nanos))
                .then_with(|| left.audit_id.cmp(&right.audit_id));
            if self.descending {
                order.reverse()
            } else {
                order
            }
        });

        AuditPage {
            read: entries.len(),
            matched: matched.len(),
            records: matched
                .into_iter()
                .skip(self.offset)
                .take(self.limit)
                .cloned()
                .collect(),
            groups,
            actions: actions.into_iter().map(str::to_string).collect(),
        }
    }

    /// Whether the record is who the query stands at.
    fn who(&self, entry: &AuditEntry) -> bool {
        let located = match (&self.location, &entry.location) {
            (Some(asked), Some(at)) => Scope::new(asked).contains(Scope::new(at)),
            (Some(_), None) => false,
            (None, _) => true,
        };
        let hosted = self
            .host
            .as_ref()
            .is_none_or(|host| entry.location.is_none() && &entry.host == host);
        let program = self
            .program
            .as_ref()
            .is_none_or(|program| &entry.program == program);

        located && hosted && program
    }

    /// Whether the record passes the filters that are not who.
    fn narrowed(&self, entry: &AuditEntry) -> bool {
        self.pattern
            .as_ref()
            .is_none_or(|pattern| matches(entry.location.as_deref().unwrap_or(""), pattern))
            && self
                .severity
                .as_ref()
                .is_none_or(|severity| &entry.severity == severity)
            && self.from.is_none_or(|from| entry.at_nanos >= from)
            && self.to.is_none_or(|to| entry.at_nanos <= to)
    }

    /// The groups one step down from where the query stands.
    fn groups(&self, matched: &[&AuditEntry]) -> Vec<AuditGroup> {
        let mut groups: BTreeMap<(u8, String), AuditGroup> = BTreeMap::new();

        for entry in matched {
            let (rank, kind, who) = self.group_of(entry);
            let group = groups.entry((rank, who.clone())).or_insert(AuditGroup {
                kind,
                who,
                count: 0,
                warnings: 0,
                errors: 0,
                latest: String::new(),
                hidden: false,
            });
            group.count += 1;
            group.hidden |= entry.hidden;
            group.warnings += usize::from(entry.severity == "warning");
            group.errors += usize::from(entry.severity == "error");
            if entry.at > group.latest {
                group.latest.clone_from(&entry.at);
            }
        }

        groups.into_values().collect()
    }

    /// Which group a record falls in, and the rank its kind sorts by.
    fn group_of(&self, entry: &AuditEntry) -> (u8, &'static str, String) {
        let program = || (3, "program", entry.program.clone());

        if self.host.is_some() {
            return program();
        }
        let Some(at) = entry.location.as_deref() else {
            return (4, "host", entry.host.clone());
        };
        let Some(asked) = self.location.as_deref() else {
            return (0, "cluster", scope_of(Scope::new(at).segments().take(1)));
        };

        let (asked, at) = (Scope::new(asked), Scope::new(at));
        if asked.path() == at.path() {
            program()
        } else if asked.node().is_none() && at.node().is_some() {
            (1, "node", scope_of(at.segments().take(3)))
        } else {
            (2, "scope", scope_of(at.segments()))
        }
    }
}

/// Segments as a scope, `xmip:///` and the path.
fn scope_of<'a>(segments: impl Iterator<Item = &'a str>) -> String {
    format!("xmip:///{}", segments.collect::<Vec<_>>().join("/"))
}

fn refusal(key: &str, value: &str, words: &str) -> String {
    format!("REFUSED: {key} {value:?} is none of {words}.")
}

fn word(key: &str, value: &str, words: &[&str]) -> Result<String, String> {
    let lower = value.to_lowercase();
    words
        .iter()
        .find(|word| **word == lower)
        .map(|word| (*word).to_string())
        .ok_or_else(|| refusal(key, value, &words.join(", ")))
}

fn number(key: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("REFUSED: {key} {value:?} is not a whole number."))
}

/// A moment: RFC 3339, or a date, or a date and a time with no zone, read
/// as UTC — what a browser's date and time box sends.
fn moment(key: &str, value: &str) -> Result<i128, String> {
    // The time follows the ten characters of the date; a zone is a Z or an
    // offset's sign after it.
    let zoneless = value
        .get(10..)
        .is_some_and(|time| !time.ends_with(['Z', 'z']) && !time.contains(['+', '-']));
    let completed = match (value.len(), zoneless) {
        (10, _) => format!("{value}T00:00:00Z"),
        (16, true) => format!("{value}:00Z"),
        (_, true) => format!("{value}Z"),
        _ => value.to_string(),
    };

    read_rfc3339(&completed).ok_or_else(|| {
        format!("REFUSED: {key} {value:?} is not a time; write 2026-09-29T14:00:00Z.")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use configure::fixture::test_cluster;

    fn entry(id: &str, at: i128, location: Option<&str>, program: &str) -> AuditEntry {
        AuditEntry {
            audit_id: id.to_string(),
            at: format!("t{at:04}"),
            at_nanos: at,
            program: program.to_string(),
            host: "edge-01".to_string(),
            location: location.map(str::to_string),
            action: "start".to_string(),
            phase: "begin".to_string(),
            severity: "information".to_string(),
            ..AuditEntry::default()
        }
    }

    /// The names the store is written with, from the test cluster: its own
    /// cluster and first node, a second cluster with a node named after
    /// the first, and a cluster whose name the first's is a prefix of.
    struct Names {
        cluster: String,
        node: String,
        other: String,
        later: String,
        longer: String,
    }

    impl Names {
        fn read() -> Self {
            let cluster = test_cluster();
            Self {
                node: cluster.node(0).name.clone(),
                other: cluster.other(),
                later: cluster.node(1).name.clone(),
                longer: format!("{}0", cluster.name),
                cluster: cluster.name,
            }
        }

        fn root(&self) -> String {
            format!("xmip:///{}", self.cluster)
        }

        fn at(&self) -> String {
            format!("{}/node/{}", self.root(), self.node)
        }

        fn node_program(&self) -> String {
            program(&self.cluster, &format!("node-{}", self.node))
        }
    }

    /// The name a playground program of `cluster` runs as (ADR-0053).
    fn program(cluster: &str, rest: &str) -> String {
        format!("xmip-playground-{cluster}-{rest}")
    }

    fn store() -> Vec<AuditEntry> {
        let names = Names::read();
        let (root, at, node) = (names.root(), names.at(), names.node_program());
        let mut failed = entry("4", 4, Some(&at), &node);
        failed.severity = "error".to_string();
        failed.phase = "failure".to_string();
        failed.action = "publish".to_string();
        let other = format!("xmip:///{}/node/{}", names.other, names.later);
        let longer = format!("xmip:///{}", names.longer);
        vec![
            entry("1", 1, Some(&root), &program(&names.cluster, "roll")),
            entry("2", 2, Some(&root), &program(&names.cluster, "cluster")),
            entry("3", 3, Some(&at), &node),
            failed,
            entry(
                "5",
                5,
                Some(&other),
                &program(&names.other, &format!("node-{}", names.later)),
            ),
            entry("6", 6, None, "Xmip"),
            entry("7", 7, Some(&longer), &program(&names.longer, "roll")),
        ]
    }

    fn ask(pairs: &[(&str, &str)]) -> AuditPage {
        AuditQuery::from_pairs(pairs.iter().copied())
            .expect("a query")
            .ask(&store())
    }

    fn ids(page: &AuditPage) -> Vec<&str> {
        page.records
            .iter()
            .map(|entry| entry.audit_id.as_str())
            .collect()
    }

    fn groups(page: &AuditPage) -> Vec<(&str, &str, usize)> {
        page.groups
            .iter()
            .map(|group| (group.kind, group.who.as_str(), group.count))
            .collect()
    }

    #[test]
    fn newest_first_is_the_default_and_the_top_groups_are_clusters_and_hosts() {
        let page = ask(&[]);
        let names = Names::read();
        let (other, longer) = (
            format!("xmip:///{}", names.other),
            format!("xmip:///{}", names.longer),
        );
        let mut clusters = [
            ("cluster", names.root(), 4),
            ("cluster", longer, 1),
            ("cluster", other, 1),
        ];
        clusters.sort();
        let mut wanted: Vec<(&str, &str, usize)> = clusters
            .iter()
            .map(|(kind, who, count)| (*kind, who.as_str(), *count))
            .collect();
        wanted.push(("host", "edge-01", 1));

        assert_eq!(ids(&page), ["7", "6", "5", "4", "3", "2", "1"]);
        assert_eq!(groups(&page), wanted);
    }

    #[test]
    fn a_cluster_groups_its_nodes_and_its_own_programs_by_the_declared_scope() {
        let names = Names::read();
        let page = ask(&[("location", &names.root())]);

        assert_eq!(
            ids(&page),
            ["4", "3", "2", "1"],
            "a cluster whose name is longer is not beneath it"
        );
        let (cluster, roll) = (
            program(&names.cluster, "cluster"),
            program(&names.cluster, "roll"),
        );
        assert_eq!(
            groups(&page),
            [
                ("node", names.at().as_str(), 2),
                ("program", cluster.as_str(), 1),
                ("program", roll.as_str(), 1),
            ]
        );
        assert_eq!(page.groups[0].errors, 1);
    }

    #[test]
    fn a_node_groups_its_programs_and_a_program_is_the_bottom() {
        let names = Names::read();
        let (at, running) = (names.at(), names.node_program());
        let node = ask(&[("location", &at)]);
        assert_eq!(groups(&node), [("program", running.as_str(), 2)]);

        let program = ask(&[("location", &at), ("program", &running)]);
        assert_eq!(ids(&program), ["4", "3"]);
        assert!(program.groups.is_empty());
    }

    #[test]
    fn a_host_holds_the_records_that_declared_no_location() {
        let page = ask(&[("host", "edge-01")]);

        assert_eq!(ids(&page), ["6"]);
        assert_eq!(groups(&page), [("program", "Xmip", 1)]);
    }

    #[test]
    fn the_pattern_is_the_one_wildcard_over_the_location() {
        let name = Names::read().cluster;
        let (nodes, lower) = (
            format!("{name}/node/*"),
            format!("xmip:///{}", name.to_lowercase()),
        );
        assert_eq!(ids(&ask(&[("pattern", &nodes)])), ["4", "3"]);
        assert_eq!(ids(&ask(&[("pattern", &lower)])), ["2", "1"]);
        assert_eq!(
            ask(&[("pattern", "*")]).matched,
            7,
            "a star names the root too"
        );
    }

    #[test]
    fn severity_action_and_time_narrow_and_the_actions_offered_stay() {
        let page = ask(&[("severity", "Error")]);
        assert_eq!(ids(&page), ["4"]);

        let acted = ask(&[("action", "publish")]);
        assert_eq!(ids(&acted), ["4"]);
        assert_eq!(acted.actions, ["publish", "start"]);

        let from = 3_i128;
        let (low, high) = (from, 5_i128);
        let query = AuditQuery {
            from: Some(low),
            to: Some(high),
            ..AuditQuery::from_pairs([]).expect("a query")
        };
        assert_eq!(ids(&query.ask(&store())), ["5", "4", "3"]);
    }

    #[test]
    fn any_column_sorts_either_way_and_ties_fall_to_time() {
        let page = ask(&[("sort", "severity"), ("order", "ascending")]);
        assert_eq!(ids(&page).last(), Some(&"4"));

        let by_program = ask(&[("sort", "program"), ("order", "ascending")]);
        assert_eq!(ids(&by_program)[0], "6", "Xmip sorts before xmip-");

        let by_node = ask(&[("sort", "node"), ("order", "descending")]);
        assert_eq!(
            &ids(&by_node)[..3],
            ["5", "4", "3"],
            "the later node's name over the earlier's, newest first"
        );
    }

    #[test]
    fn a_page_is_bounded_and_the_rest_counted() {
        let page = ask(&[("offset", "2"), ("limit", "2")]);

        assert_eq!(ids(&page), ["5", "4"]);
        assert_eq!(page.matched, 7);
        assert_eq!(page.read, 7);
        let most = AuditQuery::from_pairs([("limit", "99999")]).expect("a query");
        assert_eq!(most.limit, MOST);
    }

    #[test]
    fn a_hidden_run_is_left_out_until_included_and_a_name_hides_nothing() {
        let names = Names::read();
        // A cluster of its own for the run, beside every cluster the store has.
        let run = format!("{}-run", names.other);
        let second = format!("xmip:///{run}");
        let mut entries = store();
        let mut hidden = entry(
            "8",
            8,
            Some(&format!("{second}/node/{}", names.node)),
            &program(&run, &format!("node-{}", names.node)),
        );
        hidden.hidden = true;
        entries.push(hidden);
        // Its roll declared nothing, and is shown like any other: a name hides
        // nothing.
        entries.push(entry("9", 9, Some(&second), &program(&run, "roll")));
        let ask = |pairs: &[(&str, &str)]| {
            AuditQuery::from_pairs(pairs.iter().copied())
                .expect("a query")
                .ask(&entries)
        };

        let left_out = ask(&[]);
        assert_eq!((left_out.read, left_out.matched), (8, 8));
        assert!(!ids(&left_out).contains(&"8"));
        assert!(
            ids(&ask(&[("record", "8")])).is_empty(),
            "not even by its id"
        );
        let shown = ask(&[("location", &second)]);
        assert_eq!(ids(&shown), ["9"]);

        let included = ask(&[("hidden", "include")]);
        assert_eq!(included.matched, 9);
        let groups: Vec<(&str, bool)> = included
            .groups
            .iter()
            .map(|group| (group.who.as_str(), group.hidden))
            .collect();
        assert!(groups.contains(&(second.as_str(), true)), "{groups:?}");
        let root = names.root();
        assert!(groups.contains(&(root.as_str(), false)), "{groups:?}");
        assert_eq!(ask(&[("hidden", "exclude")]).matched, 8);
        assert!(
            AuditQuery::from_pairs([("hidden", "yes")])
                .expect_err("refused")
                .starts_with("REFUSED")
        );
    }

    #[test]
    fn one_record_is_asked_by_its_identifier_whatever_else_is_asked() {
        let page = ask(&[("record", "6"), ("location", &Names::read().root())]);

        assert_eq!(ids(&page), ["6"]);
    }

    #[test]
    fn a_word_it_does_not_take_is_refused_in_one_sentence() {
        for pairs in [
            [("colour", "red")],
            [("severity", "fatal")],
            [("sort", "when")],
            [("from", "yesterday")],
            [("limit", "ten")],
        ] {
            let refusal = AuditQuery::from_pairs(pairs).expect_err("refused");
            assert!(refusal.starts_with("REFUSED: "), "{refusal}");
        }
    }

    #[test]
    fn a_time_without_a_zone_is_utc_and_a_date_is_its_midnight() {
        let at = |text| moment("from", text).expect("a time");

        assert_eq!(at("2026-09-29"), at("2026-09-29T00:00:00Z"));
        assert_eq!(at("2026-09-29T14:00"), at("2026-09-29T14:00:00Z"));
        assert_eq!(at("2026-09-29T14:00:05"), at("2026-09-29T14:00:05Z"));
        assert_eq!(at("2026-09-29T16:00:00+02:00"), at("2026-09-29T14:00:00Z"));
    }
}
