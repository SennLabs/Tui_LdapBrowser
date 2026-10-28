//! Result columns and type-aware sorting (plan section 5.6.7).
//!
//! A column is an attribute name, or one of the virtual columns `parent` (parent DN),
//! `members` (member count) and `kind` (object type). The name column is always first and is
//! not configurable.

use chrono::{NaiveDateTime, TimeZone, Utc};

use crate::ldap::decode;
use crate::ldap::flavor::Flavor;
use crate::ldap::model::{self, Hit, Value};

pub const VIRTUAL: &[&str] = &["parent", "members", "kind"];
/// Result kinds that have their own column defaults.
pub const KINDS: &[&str] = &["users", "groups", "other"];

pub fn is_virtual(c: &str) -> bool {
    VIRTUAL.iter().any(|v| v.eq_ignore_ascii_case(c))
}

/// Built-in column defaults per flavor and result kind.
pub fn default_columns(flavor: Flavor, kind: &str) -> Vec<String> {
    let cols: &[&str] = match (flavor, kind) {
        (Flavor::Ad, "users") => &["sAMAccountName", "mail", "userAccountControl", "lastLogonTimestamp"],
        (Flavor::Ad, "groups") => &["description", "groupType", "members"],
        (Flavor::Lldap, "users") => &["uid", "mail"],
        (_, "users") => &["uid", "mail"],
        (_, "groups") => &["description", "members"],
        _ => &["description", "parent"],
    };
    cols.iter().map(|s| s.to_string()).collect()
}

/// Attributes to request from the server so that every column can be filled.
pub fn needed_attrs(columns: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |a: &str| {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(a)) {
            out.push(a.to_string());
        }
    };
    for c in columns {
        match c.to_ascii_lowercase().as_str() {
            "parent" | "kind" => {}
            "members" => {
                push("member");
                push("uniqueMember");
                push("memberUid");
            }
            _ => push(c),
        }
    }
    out
}

/// Attributes offered in the column picker, beyond whatever is already configured.
pub fn candidates(flavor: Flavor) -> Vec<String> {
    let mut v: Vec<&str> = vec!["parent", "members", "kind", "mail", "description", "cn", "displayName"];
    match flavor {
        Flavor::Ad => v.extend([
            "sAMAccountName",
            "userPrincipalName",
            "userAccountControl",
            "lastLogonTimestamp",
            "pwdLastSet",
            "accountExpires",
            "whenCreated",
            "whenChanged",
            "department",
            "title",
            "manager",
            "groupType",
            "objectSid",
            "employeeID",
            "telephoneNumber",
        ]),
        Flavor::Lldap => v.extend(["uid", "givenName", "sn", "createTimestamp", "modifyTimestamp"]),
        _ => v.extend([
            "uid",
            "uidNumber",
            "gidNumber",
            "givenName",
            "sn",
            "createTimestamp",
            "modifyTimestamp",
            "employeeNumber",
            "telephoneNumber",
        ]),
    }
    v.into_iter().map(str::to_string).collect()
}

/// The text shown in a cell: decoded forms (dates, flag names, SIDs) are preferred over raw values.
pub fn cell_text(hit: &Hit, column: &str) -> String {
    match column.to_ascii_lowercase().as_str() {
        "parent" => model::parent_dn(&hit.dn).unwrap_or_default(),
        "kind" => kind_label(hit).to_string(),
        "members" => {
            let n = ["member", "uniquemember", "memberuid"].iter().map(|a| hit.values(a).len()).sum::<usize>();
            let partial = ["member", "uniquemember", "memberuid"].iter().any(|a| hit.is_partial(a));
            if n == 0 && hit.kind != model::EntryKind::Group {
                String::new()
            } else if partial {
                format!("{n}+")
            } else {
                n.to_string()
            }
        }
        _ => {
            let vals = hit.values(column);
            let shown: Vec<String> = vals
                .iter()
                .take(3)
                .map(|v| match v {
                    Value::Text(_) => decode::annotate(column, v).unwrap_or_else(|| decode::display_value(column, v)),
                    Value::Binary(_) => decode::display_value(column, v),
                })
                .collect();
            let mut s = shown.join("; ");
            if vals.len() > 3 {
                s.push_str(&format!(" (+{})", vals.len() - 3));
            }
            s
        }
    }
}

fn kind_label(hit: &Hit) -> &'static str {
    use model::EntryKind::*;
    match hit.kind {
        Domain => "domain",
        OrgUnit => "OU",
        Container => "container",
        User => "user",
        Computer => "computer",
        Group => "group",
        Gpo => "GPO",
        Builtin => "builtin",
        Referral => "referral",
        Other => "other",
    }
}

/// Comparable form of a cell. `None` means missing / "never", which always sorts last.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SortKey {
    Time(i64),
    Num(i128),
    Text(String),
}

pub fn sort_key(hit: &Hit, column: Option<&str>) -> Option<SortKey> {
    let Some(column) = column else {
        return Some(SortKey::Text(hit.name.to_lowercase()));
    };
    match column.to_ascii_lowercase().as_str() {
        "parent" => Some(SortKey::Text(model::parent_dn(&hit.dn).unwrap_or_default().to_lowercase())),
        "kind" => Some(SortKey::Num(hit.kind.sort_rank() as i128)),
        "members" => {
            let n = ["member", "uniquemember", "memberuid"].iter().map(|a| hit.values(a).len()).sum::<usize>();
            Some(SortKey::Num(n as i128))
        }
        col => {
            let v = hit.values(col).first()?;
            let Value::Text(s) = v else {
                return Some(SortKey::Text(decode::display_value(col, v)));
            };
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if decode::is_filetime_attr(col) {
                let n: i64 = s.parse().ok()?;
                return (n != 0 && n != i64::MAX).then_some(SortKey::Time(n / 10_000_000 - 11_644_473_600));
            }
            if decode::is_generalized_time_attr(col) {
                return generalized_epoch(s).map(SortKey::Time);
            }
            if let Ok(n) = s.parse::<i128>() {
                return Some(SortKey::Num(n));
            }
            Some(SortKey::Text(s.to_lowercase()))
        }
    }
}

fn generalized_epoch(s: &str) -> Option<i64> {
    let core = s.trim_end_matches('Z');
    let core = core.split(['.', ',']).next()?;
    if core.len() != 14 {
        return None;
    }
    let ndt = NaiveDateTime::parse_from_str(core, "%Y%m%d%H%M%S").ok()?;
    Some(Utc.from_utc_datetime(&ndt).timestamp())
}

/// Display order of `hits` sorted by `column` (`None` = name). Missing values go last either way.
pub fn sort_order(hits: &[Hit], column: Option<&str>, descending: bool) -> Vec<usize> {
    let mut present: Vec<(SortKey, usize)> = Vec::new();
    let mut missing: Vec<usize> = Vec::new();
    for (i, h) in hits.iter().enumerate() {
        match sort_key(h, column) {
            Some(k) => present.push((k, i)),
            None => missing.push(i),
        }
    }
    present.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    if descending {
        present.reverse();
    }
    present.into_iter().map(|(_, i)| i).chain(missing).collect()
}

/// Parses `results.sort` from config: `"name"`, `"attr"` or `"attr:desc"`.
pub fn parse_sort(spec: &str) -> (Option<String>, bool) {
    let (col, dir) = spec.split_once(':').unwrap_or((spec, "asc"));
    let col = col.trim();
    let col = (!col.is_empty() && !col.eq_ignore_ascii_case("name")).then(|| col.to_string());
    (col, dir.trim().eq_ignore_ascii_case("desc"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::model::EntryKind;

    fn hit(name: &str, attrs: &[(&str, &str)]) -> Hit {
        let mut h = Hit::bare("cn=x,dc=y", EntryKind::User, name.into(), String::new());
        for (k, v) in attrs {
            h.values.insert(k.to_ascii_lowercase(), vec![Value::Text(v.to_string())]);
        }
        h
    }

    #[test]
    fn defaults_and_needed_attrs() {
        assert_eq!(default_columns(Flavor::Ad, "groups"), ["description", "groupType", "members"]);
        assert_eq!(default_columns(Flavor::OpenLdap, "users"), ["uid", "mail"]);
        let need = needed_attrs(&["members".into(), "parent".into(), "mail".into(), "MAIL".into()]);
        assert_eq!(need, ["member", "uniqueMember", "memberUid", "mail"]);
        assert!(is_virtual("Parent") && !is_virtual("mail"));
    }

    #[test]
    fn sort_is_type_aware_with_missing_last() {
        let hits = vec![
            hit("b", &[("lastLogonTimestamp", "133520123450000000"), ("uidNumber", "10")]),
            hit("a", &[("lastLogonTimestamp", "0"), ("uidNumber", "9")]),
            hit("c", &[("lastLogonTimestamp", "133000000000000000"), ("uidNumber", "100")]),
            hit("d", &[]),
        ];
        assert_eq!(sort_order(&hits, None, false), [1, 0, 2, 3]);
        assert_eq!(sort_order(&hits, Some("lastLogonTimestamp"), false), [2, 0, 1, 3]);
        assert_eq!(sort_order(&hits, Some("lastLogonTimestamp"), true), [0, 2, 1, 3], "never stays last");
        assert_eq!(sort_order(&hits, Some("uidNumber"), false), [1, 0, 2, 3], "numeric, not lexical");
        assert_eq!(sort_order(&hits, Some("uidNumber"), true), [2, 0, 1, 3]);
    }

    #[test]
    fn generalized_time_sorts_chronologically() {
        let hits = vec![
            hit("a", &[("whenCreated", "20240301000000.0Z")]),
            hit("b", &[("whenCreated", "20230301000000.0Z")]),
            hit("c", &[("whenCreated", "garbage")]),
        ];
        assert_eq!(sort_order(&hits, Some("whenCreated"), false), [1, 0, 2]);
    }

    #[test]
    fn cells_and_counts() {
        let mut g = Hit::bare("cn=g,ou=groups,dc=x", EntryKind::Group, "g".into(), String::new());
        g.values.insert("member".into(), vec![Value::Text("a".into()), Value::Text("b".into())]);
        g.partial.push("member".into());
        assert_eq!(cell_text(&g, "members"), "2+");
        assert_eq!(cell_text(&g, "parent"), "ou=groups,dc=x");
        assert_eq!(cell_text(&g, "kind"), "group");
        let u = hit("u", &[("userAccountControl", "514"), ("lastLogon", "0")]);
        assert_eq!(cell_text(&u, "userAccountControl"), "ACCOUNTDISABLE | NORMAL_ACCOUNT");
        assert_eq!(cell_text(&u, "lastLogon"), "never");
        assert_eq!(cell_text(&u, "nothere"), "");
        assert_eq!(parse_sort("lastLogon:desc"), (Some("lastLogon".into()), true));
        assert_eq!(parse_sort("name"), (None, false));
    }
}
