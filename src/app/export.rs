//! Export of entries, result lists, membership trees and tree children (plan section 5.6.1).
//!
//! Serialisation is pure and synchronous: everything exported is already in memory.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use super::columns;
use crate::ldap::decode;
use crate::ldap::model::{Entry, EntryKind, Hit, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Ldif,
    Json,
    Csv,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Ldif => "LDIF",
            Format::Json => "JSON",
            Format::Csv => "CSV",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::Ldif => "ldif",
            Format::Json => "json",
            Format::Csv => "csv",
        }
    }
}

/// What is being exported, captured at the moment `e` is pressed.
#[derive(Debug, Clone)]
pub enum What {
    Entry(Box<Entry>),
    /// Hits in display order with the columns shown.
    Results {
        title: String,
        columns: Vec<String>,
        hits: Vec<Hit>,
    },
    /// Membership tree rows: (depth, hit, cycle).
    Tree {
        title: String,
        rows: Vec<(usize, Hit, bool)>,
    },
    /// Loaded children of a tree node.
    Children {
        dn: String,
        children: Vec<(String, EntryKind)>,
    },
}

impl What {
    pub fn formats(&self) -> &'static [Format] {
        match self {
            What::Entry(_) => &[Format::Ldif, Format::Json, Format::Csv],
            _ => &[Format::Json, Format::Csv],
        }
    }

    pub fn describe(&self) -> String {
        match self {
            What::Entry(e) => format!("entry {}", e.dn),
            What::Results { title, hits, .. } => format!("{} ({} rows)", title, hits.len()),
            What::Tree { title, rows } => format!("{} tree ({} rows)", title, rows.len()),
            What::Children { dn, children } => format!("{} children of {dn}", children.len()),
        }
    }

    /// Suggested file name (without directory) for a format.
    pub fn default_name(&self, format: Format) -> String {
        let stem = match self {
            What::Entry(e) => crate::ldap::model::rdn_value(&e.dn),
            What::Results { title, .. } | What::Tree { title, .. } => title.clone(),
            What::Children { dn, .. } => crate::ldap::model::rdn_value(dn),
        };
        format!("{}.{}", sanitize(&stem), format.extension())
    }

    pub fn row_count(&self) -> usize {
        match self {
            What::Entry(_) => 1,
            What::Results { hits, .. } => hits.len(),
            What::Tree { rows, .. } => rows.len(),
            What::Children { children, .. } => children.len(),
        }
    }
}

fn sanitize(s: &str) -> String {
    let mut out: String =
        s.chars().map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).collect();
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() { "export".into() } else { out.chars().take(60).collect() }
}

/// Renders `what` in `format`. `decoded` writes readable forms (dates, flag names, GUIDs) for
/// JSON and CSV instead of raw values; LDIF is always raw.
pub fn render(what: &What, format: Format, decoded: bool) -> String {
    match (what, format) {
        (What::Entry(e), Format::Ldif) => ldif_entry(e),
        (What::Entry(e), Format::Json) => {
            serde_json::to_string_pretty(&json_entry(e, decoded)).unwrap_or_default() + "\n"
        }
        (What::Entry(e), Format::Csv) => {
            let header: Vec<String> =
                std::iter::once("dn".to_string()).chain(e.attrs.iter().map(|a| a.name.clone())).collect();
            let row: Vec<String> =
                std::iter::once(e.dn.clone())
                    .chain(e.attrs.iter().map(|a| {
                        a.values.iter().map(|v| value_text(&a.name, v, decoded)).collect::<Vec<_>>().join("; ")
                    }))
                    .collect();
            csv(&[header, row])
        }
        (What::Results { columns, hits, .. }, Format::Json) => {
            let rows: Vec<serde_json::Value> = hits.iter().map(|h| json_hit(h, columns, decoded, None)).collect();
            serde_json::to_string_pretty(&rows).unwrap_or_default() + "\n"
        }
        (What::Results { columns, hits, .. }, Format::Csv) => {
            let mut rows = vec![hit_header(columns, false)];
            rows.extend(hits.iter().map(|h| hit_row(h, columns, decoded, None)));
            csv(&rows)
        }
        (What::Tree { rows: trows, .. }, Format::Json) => {
            let rows: Vec<serde_json::Value> =
                trows.iter().map(|(d, h, c)| json_hit(h, &[], decoded, Some((*d, *c)))).collect();
            serde_json::to_string_pretty(&rows).unwrap_or_default() + "\n"
        }
        (What::Tree { rows: trows, .. }, Format::Csv) => {
            let mut rows = vec![hit_header(&[], true)];
            rows.extend(trows.iter().map(|(d, h, c)| hit_row(h, &[], decoded, Some((*d, *c)))));
            csv(&rows)
        }
        (What::Children { children, .. }, Format::Json) => {
            let rows: Vec<serde_json::Value> = children
                .iter()
                .map(|(dn, kind)| {
                    serde_json::json!({ "dn": dn, "rdn": crate::ldap::model::rdn(dn), "kind": kind_name(*kind) })
                })
                .collect();
            serde_json::to_string_pretty(&rows).unwrap_or_default() + "\n"
        }
        (What::Children { children, .. }, Format::Csv) => {
            let mut rows = vec![vec!["dn".to_string(), "rdn".to_string(), "kind".to_string()]];
            rows.extend(
                children
                    .iter()
                    .map(|(dn, kind)| vec![dn.clone(), crate::ldap::model::rdn(dn), kind_name(*kind).into()]),
            );
            csv(&rows)
        }
        (what, Format::Ldif) => {
            // Not offered in the dialog; fall back to JSON rather than inventing partial LDIF.
            render(what, Format::Json, decoded)
        }
    }
}

fn kind_name(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Domain => "domain",
        EntryKind::OrgUnit => "organizationalUnit",
        EntryKind::Container => "container",
        EntryKind::User => "user",
        EntryKind::Computer => "computer",
        EntryKind::Group => "group",
        EntryKind::Gpo => "groupPolicy",
        EntryKind::Builtin => "builtin",
        EntryKind::Referral => "referral",
        EntryKind::Other => "other",
    }
}

fn value_text(attr: &str, v: &Value, decoded: bool) -> String {
    if decode::is_secret_attr(attr) {
        return "<redacted>".into();
    }
    match v {
        Value::Text(s) => {
            if decoded {
                decode::annotate(attr, v).unwrap_or_else(|| s.clone())
            } else {
                s.clone()
            }
        }
        Value::Binary(b) => {
            if decoded && let Some(a) = decode::annotate(attr, v) {
                a
            } else {
                B64.encode(b)
            }
        }
    }
}

fn json_value(attr: &str, v: &Value, decoded: bool) -> serde_json::Value {
    if decode::is_secret_attr(attr) {
        return serde_json::Value::String("<redacted>".into());
    }
    match v {
        Value::Text(_) => serde_json::Value::String(value_text(attr, v, decoded)),
        Value::Binary(b) => {
            if decoded && let Some(a) = decode::annotate(attr, v) {
                serde_json::Value::String(a)
            } else {
                serde_json::json!({ "base64": B64.encode(b) })
            }
        }
    }
}

fn json_entry(e: &Entry, decoded: bool) -> serde_json::Value {
    let mut attrs = serde_json::Map::new();
    for a in &e.attrs {
        let vals: Vec<serde_json::Value> = a.values.iter().map(|v| json_value(&a.name, v, decoded)).collect();
        attrs.insert(a.name.clone(), serde_json::Value::Array(vals));
    }
    serde_json::json!({ "dn": e.dn, "attributes": attrs })
}

fn hit_header(columns: &[String], tree: bool) -> Vec<String> {
    let mut h = Vec::new();
    if tree {
        h.push("depth".into());
    }
    h.extend(["dn", "name", "kind", "tag"].map(String::from));
    if tree {
        h.push("cycle".into());
    }
    h.extend(columns.iter().cloned());
    h
}

fn hit_row(h: &Hit, columns: &[String], decoded: bool, tree: Option<(usize, bool)>) -> Vec<String> {
    let mut row = Vec::new();
    if let Some((d, _)) = tree {
        row.push(d.to_string());
    }
    row.extend([h.dn.clone(), h.name.clone(), kind_name(h.kind).into(), h.tag.clone().unwrap_or_default()]);
    if let Some((_, c)) = tree {
        row.push(if c { "yes".into() } else { String::new() });
    }
    for c in columns {
        row.push(hit_cell(h, c, decoded));
    }
    row
}

fn hit_cell(h: &Hit, column: &str, decoded: bool) -> String {
    if columns::is_virtual(column) || decoded {
        return columns::cell_text(h, column);
    }
    h.values(column).iter().map(|v| value_text(column, v, false)).collect::<Vec<_>>().join("; ")
}

fn json_hit(h: &Hit, columns: &[String], decoded: bool, tree: Option<(usize, bool)>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some((d, c)) = tree {
        obj.insert("depth".into(), d.into());
        obj.insert("cycle".into(), c.into());
    }
    obj.insert("dn".into(), h.dn.clone().into());
    obj.insert("name".into(), h.name.clone().into());
    obj.insert("kind".into(), kind_name(h.kind).into());
    if let Some(t) = &h.tag {
        obj.insert("tag".into(), t.clone().into());
    }
    if !columns.is_empty() {
        let mut attrs = serde_json::Map::new();
        for c in columns {
            if columns::is_virtual(c) {
                attrs.insert(c.clone(), columns::cell_text(h, c).into());
            } else {
                let vals: Vec<serde_json::Value> = h.values(c).iter().map(|v| json_value(c, v, decoded)).collect();
                attrs.insert(c.clone(), serde_json::Value::Array(vals));
            }
        }
        obj.insert("attributes".into(), serde_json::Value::Object(attrs));
    }
    serde_json::Value::Object(obj)
}

// ---------------------------------------------------------------------------------------------
// LDIF (RFC 2849)

fn ldif_entry(e: &Entry) -> String {
    let mut out = String::new();
    ldif_line(&mut out, "dn", &Value::Text(e.dn.clone()));
    for a in &e.attrs {
        if decode::is_secret_attr(&a.name) {
            // '<' cannot start an LDIF value, so the redaction is a comment rather than a value.
            out.push_str(&format!("# {}: {} value(s) redacted\n", a.name, a.values.len()));
            continue;
        }
        for v in &a.values {
            ldif_line(&mut out, &a.name, v);
        }
    }
    out.push('\n');
    out
}

fn ldif_line(out: &mut String, name: &str, v: &Value) {
    let line = match v {
        Value::Text(s) if ldif_safe(s) => format!("{name}: {s}"),
        Value::Text(s) => format!("{name}:: {}", B64.encode(s.as_bytes())),
        Value::Binary(b) => format!("{name}:: {}", B64.encode(b)),
    };
    out.push_str(&fold(&line));
    out.push('\n');
}

/// SAFE-STRING: ASCII, no NUL/CR/LF, and not starting with space, colon or '<'.
fn ldif_safe(s: &str) -> bool {
    !s.is_empty()
        && s.is_ascii()
        && !s.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n'))
        && !s.starts_with([' ', ':', '<'])
        && !s.ends_with(' ')
}

/// Folds at 76 columns; continuation lines start with one space.
fn fold(line: &str) -> String {
    const WIDTH: usize = 76;
    let bytes = line.as_bytes();
    if bytes.len() <= WIDTH {
        return line.to_string();
    }
    let mut out = String::new();
    let mut i = 0;
    let mut first = true;
    while i < bytes.len() {
        let take = if first { WIDTH } else { WIDTH - 1 };
        let mut end = (i + take).min(bytes.len());
        while end < bytes.len() && !line.is_char_boundary(end) {
            end -= 1;
        }
        if !first {
            out.push_str("\n ");
        }
        out.push_str(&line[i..end]);
        i = end;
        first = false;
    }
    out
}

// ---------------------------------------------------------------------------------------------
// CSV (RFC 4180)

fn csv(rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    for r in rows {
        let cells: Vec<String> = r.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&cells.join(","));
        out.push_str("\r\n");
    }
    out
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

// ---------------------------------------------------------------------------------------------
// Paths

pub fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
    {
        return home.join(rest);
    }
    if p == "~"
        && let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
    {
        return home;
    }
    PathBuf::from(p)
}

/// Tab completion for a path being typed. Returns the completed text and a note for the user.
pub fn complete_path(typed: &str) -> (String, Option<String>) {
    let expanded = expand_home(typed);
    let (dir, prefix) = if typed.ends_with('/') {
        (expanded.clone(), String::new())
    } else {
        (
            expanded.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(".")),
            expanded.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default(),
        )
    };
    let Ok(rd) = std::fs::read_dir(if dir.as_os_str().is_empty() { Path::new(".") } else { &dir }) else {
        return (typed.to_string(), Some("directory not found".into()));
    };
    let mut matches: Vec<(String, bool)> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            (name.starts_with(&prefix) && (prefix.starts_with('.') || !name.starts_with('.')))
                .then(|| (name, e.path().is_dir()))
        })
        .collect();
    matches.sort();
    let typed_dir = match typed.rfind('/') {
        Some(i) => &typed[..=i],
        None => "",
    };
    match matches.len() {
        0 => (typed.to_string(), Some("no match".into())),
        1 => {
            let (name, is_dir) = &matches[0];
            (format!("{typed_dir}{name}{}", if *is_dir { "/" } else { "" }), None)
        }
        n => {
            let common = common_prefix(matches.iter().map(|(n, _)| n.as_str()));
            let note = matches.iter().take(8).map(|(n, _)| n.as_str()).collect::<Vec<_>>().join("  ");
            (format!("{typed_dir}{common}"), Some(format!("{n} matches: {note}{}", if n > 8 { " …" } else { "" })))
        }
    }
}

fn common_prefix<'a>(mut names: impl Iterator<Item = &'a str>) -> String {
    let Some(first) = names.next() else { return String::new() };
    let mut prefix: Vec<char> = first.chars().collect();
    for n in names {
        let keep = prefix.iter().zip(n.chars()).take_while(|(a, b)| *a == b).count();
        prefix.truncate(keep);
    }
    prefix.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::model::{self, Attribute};

    fn entry() -> Entry {
        let mut attrs = vec![
            Attribute {
                name: "objectClass".into(),
                values: vec![Value::Text("top".into()), Value::Text("user".into())],
                operational: false,
            },
            Attribute { name: "cn".into(), values: vec![Value::Text("Doe, Jane".into())], operational: false },
            Attribute {
                name: "description".into(),
                values: vec![Value::Text(" leading space".into())],
                operational: false,
            },
            Attribute { name: "givenName".into(), values: vec![Value::Text("Zoë".into())], operational: false },
            Attribute { name: "objectGUID".into(), values: vec![Value::Binary(vec![1; 16])], operational: false },
            Attribute { name: "userPassword".into(), values: vec![Value::Text("hunter2".into())], operational: false },
            Attribute { name: "pwdLastSet".into(), values: vec![Value::Text("0".into())], operational: false },
            Attribute { name: "info".into(), values: vec![Value::Text("x".repeat(100))], operational: false },
        ];
        model::sort_attrs(&mut attrs);
        Entry { dn: "CN=Doe\\, Jane,OU=Staff,DC=x".into(), attrs }
    }

    #[test]
    fn ldif_follows_rfc2849() {
        let out = render(&What::Entry(Box::new(entry())), Format::Ldif, true);
        assert!(out.starts_with("dn: CN=Doe\\, Jane,OU=Staff,DC=x\nobjectClass: top\nobjectClass: user\n"), "{out}");
        assert!(out.contains("cn: Doe, Jane\n"));
        assert!(out.contains("description:: IGxlYWRpbmcgc3BhY2U=\n"), "leading space must be base64:\n{out}");
        assert!(out.contains("givenName:: Wm/Dqw==\n"), "non-ASCII must be base64:\n{out}");
        assert!(out.contains("objectGUID:: AQEBAQEBAQEBAQEBAQEBAQ==\n"));
        assert!(out.contains("# userPassword: 1 value(s) redacted\n"), "{out}");
        assert!(!out.contains("hunter2"));
        // Folding: a 106-char line becomes 76 + continuation starting with a space.
        let folded: Vec<&str> = out.lines().filter(|l| l.starts_with("info:") || l.starts_with(' ')).collect();
        assert_eq!(folded.len(), 2, "{out}");
        assert_eq!(folded[0].len(), 76);
        assert!(folded[1].starts_with(' ') && folded[1].len() == 106 - 76 + 1);
        assert!(out.ends_with("\n\n"));
    }

    #[test]
    fn json_and_csv_entry_with_decoding_and_redaction() {
        let w = What::Entry(Box::new(entry()));
        let raw: serde_json::Value = serde_json::from_str(&render(&w, Format::Json, false)).unwrap();
        assert_eq!(raw["attributes"]["pwdLastSet"][0], "0");
        assert_eq!(raw["attributes"]["objectGUID"][0]["base64"], "AQEBAQEBAQEBAQEBAQEBAQ==");
        assert_eq!(raw["attributes"]["userPassword"][0], "<redacted>");
        let dec: serde_json::Value = serde_json::from_str(&render(&w, Format::Json, true)).unwrap();
        assert_eq!(dec["attributes"]["pwdLastSet"][0], "never");
        assert_eq!(dec["attributes"]["objectGUID"][0], "01010101-0101-0101-0101-010101010101");
        let csv = render(&w, Format::Csv, false);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("dn,objectClass,cn,"), "{csv}");
        assert!(lines[1].contains("\"CN=Doe\\, Jane,OU=Staff,DC=x\",top; user,\"Doe, Jane\","), "{csv}");
        assert!(lines[1].contains("<redacted>"));
    }

    #[test]
    fn results_and_tree_rows() {
        let mut h = Hit::bare("cn=g,ou=groups,dc=x", EntryKind::Group, "g".into(), String::new());
        h.values.insert("member".into(), vec![Value::Text("a".into()), Value::Text("b".into())]);
        h.values.insert("description".into(), vec![Value::Text("line1\nline2".into())]);
        let w = What::Results {
            title: "Groups — g".into(),
            columns: vec!["description".into(), "members".into()],
            hits: vec![h.clone()],
        };
        let csv = render(&w, Format::Csv, false);
        assert_eq!(csv.lines().next().unwrap(), "dn,name,kind,tag,description,members");
        assert!(csv.contains("\"cn=g,ou=groups,dc=x\",g,group,,\"line1\nline2\",2"), "{csv}");
        let json: serde_json::Value = serde_json::from_str(&render(&w, Format::Json, false)).unwrap();
        assert_eq!(json[0]["attributes"]["members"], "2");
        assert_eq!(json[0]["attributes"]["description"][0], "line1\nline2");
        assert_eq!(w.default_name(Format::Csv), "Groups_g.csv");

        let t = What::Tree { title: "Members of g".into(), rows: vec![(0, h.clone(), false), (1, h, true)] };
        let csv = render(&t, Format::Csv, true);
        assert_eq!(csv.lines().next().unwrap(), "depth,dn,name,kind,tag,cycle");
        assert!(csv.contains("1,\"cn=g,ou=groups,dc=x\",g,group,,yes"), "{csv}");
        let c = What::Children { dn: "ou=x,dc=y".into(), children: vec![("cn=a,ou=x,dc=y".into(), EntryKind::User)] };
        assert!(render(&c, Format::Csv, false).contains("\"cn=a,ou=x,dc=y\",cn=a,user"));
        assert_eq!(c.formats(), &[Format::Json, Format::Csv]);
    }

    #[test]
    fn path_completion() {
        let dir = std::env::temp_dir().join(format!("ldaptui-complete-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("exports")).unwrap();
        std::fs::write(dir.join("export.csv"), "").unwrap();
        std::fs::write(dir.join(".hidden"), "").unwrap();
        let base = format!("{}/", dir.display());
        let (done, note) = complete_path(&format!("{base}exp"));
        assert_eq!(done, format!("{base}export"));
        assert!(note.unwrap().starts_with("2 matches"));
        let (done, note) = complete_path(&format!("{base}exports"));
        assert_eq!(done, format!("{base}exports/"));
        assert!(note.is_none());
        let (_, note) = complete_path(&format!("{base}zzz"));
        assert_eq!(note.as_deref(), Some("no match"));
        let (done, _) = complete_path(&base);
        assert_eq!(done, format!("{base}export"), "hidden files are skipped: {done}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
