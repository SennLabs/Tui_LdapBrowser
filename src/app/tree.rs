//! Lazily loaded directory tree.

use std::collections::HashMap;

use crate::ldap::model::{self, ChildList, EntryKind};
use crate::ldap::worker::RequestId;

pub type Key = String;

pub fn key_of(dn: &str) -> Key {
    model::normalize_dn(dn)
}

/// RDN for display, with escapes resolved: `cn=Doe\2C Jane` -> `cn=Doe, Jane`.
pub fn display_rdn(dn: &str) -> String {
    let r = model::rdn(dn);
    match r.split_once('=') {
        Some((a, _)) if !r.contains('+') => format!("{}={}", a.trim(), model::rdn_value(dn)),
        _ => r,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Load {
    NotLoaded,
    Loading(RequestId),
    Loaded,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub dn: String,
    pub label: String,
    pub kind: EntryKind,
    pub expanded: bool,
    pub load: Load,
    pub children: Vec<Key>,
    pub truncated: bool,
    pub limit: usize,
    pub prefix: Option<String>,
    pub has_children: Option<bool>,
    /// Referral URL for continuation-reference leaves.
    pub referral: Option<String>,
}

impl Node {
    fn new(dn: &str, label: String, kind: EntryKind, limit: usize) -> Node {
        Node {
            dn: dn.to_string(),
            label,
            kind,
            expanded: false,
            load: Load::NotLoaded,
            children: Vec::new(),
            truncated: false,
            limit,
            prefix: None,
            has_children: None,
            referral: None,
        }
    }

    pub fn expandable(&self) -> bool {
        self.referral.is_none()
            && match self.load {
                Load::Loaded => !self.children.is_empty() || self.prefix.is_some(),
                _ => self.has_children.unwrap_or_else(|| self.kind.likely_container()),
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RowId {
    Node(Key),
    More(Key),
    Status(Key),
}

#[derive(Debug, Clone)]
pub enum Row {
    Node {
        key: Key,
        depth: usize,
    },
    /// "load more" for a truncated parent.
    More {
        parent: Key,
        depth: usize,
        shown: usize,
    },
    /// Loading / empty / error / filter indicator under a parent.
    Status {
        parent: Key,
        depth: usize,
        text: String,
        error: bool,
    },
}

impl Row {
    pub fn id(&self) -> RowId {
        match self {
            Row::Node { key, .. } => RowId::Node(key.clone()),
            Row::More { parent, .. } => RowId::More(parent.clone()),
            Row::Status { parent, .. } => RowId::Status(parent.clone()),
        }
    }
}

#[derive(Debug, Default)]
pub struct Tree {
    pub nodes: HashMap<Key, Node>,
    pub roots: Vec<Key>,
    pub selected: Option<RowId>,
    pub child_limit: usize,
}

impl Tree {
    pub fn new(roots: &[String], child_limit: usize) -> Tree {
        let mut t = Tree { child_limit, ..Default::default() };
        for r in roots {
            let k = key_of(r);
            if t.nodes.contains_key(&k) {
                continue;
            }
            t.nodes.insert(k.clone(), Node::new(r, r.clone(), EntryKind::Domain, child_limit));
            t.roots.push(k);
        }
        t.selected = t.roots.first().cloned().map(RowId::Node);
        t
    }

    pub fn get(&self, k: &str) -> Option<&Node> {
        self.nodes.get(k)
    }

    pub fn get_mut(&mut self, k: &str) -> Option<&mut Node> {
        self.nodes.get_mut(k)
    }

    pub fn rows(&self) -> Vec<Row> {
        let mut out = Vec::new();
        for r in &self.roots {
            self.push_rows(r, 0, &mut out);
        }
        out
    }

    fn push_rows(&self, k: &Key, depth: usize, out: &mut Vec<Row>) {
        let Some(n) = self.nodes.get(k) else { return };
        out.push(Row::Node { key: k.clone(), depth });
        if !n.expanded {
            return;
        }
        let d = depth + 1;
        if let Some(p) = &n.prefix {
            out.push(Row::Status {
                parent: k.clone(),
                depth: d,
                text: format!("filter: {p}*  (: to change, empty to clear)"),
                error: false,
            });
        }
        match &n.load {
            Load::Loading(_) if n.children.is_empty() => {
                out.push(Row::Status { parent: k.clone(), depth: d, text: "loading…".into(), error: false });
                return;
            }
            Load::Failed(e) => {
                out.push(Row::Status { parent: k.clone(), depth: d, text: e.clone(), error: true });
                return;
            }
            Load::Loaded if n.children.is_empty() && n.prefix.is_none() => {
                out.push(Row::Status { parent: k.clone(), depth: d, text: "(no children)".into(), error: false });
                return;
            }
            Load::Loaded if n.children.is_empty() => {
                out.push(Row::Status { parent: k.clone(), depth: d, text: "(no matches)".into(), error: false });
                return;
            }
            _ => {}
        }
        for c in &n.children {
            self.push_rows(c, d, out);
        }
        if n.truncated {
            out.push(Row::More { parent: k.clone(), depth: d, shown: n.children.len() });
        }
    }

    pub fn selected_index(&self, rows: &[Row]) -> usize {
        self.selected.as_ref().and_then(|s| rows.iter().position(|r| &r.id() == s)).unwrap_or(0)
    }

    pub fn selected_key(&self) -> Option<&Key> {
        match &self.selected {
            Some(RowId::Node(k)) => Some(k),
            _ => None,
        }
    }

    pub fn selected_node(&self) -> Option<&Node> {
        self.selected_key().and_then(|k| self.nodes.get(k))
    }

    pub fn select_index(&mut self, rows: &[Row], idx: usize) {
        if let Some(r) = rows.get(idx.min(rows.len().saturating_sub(1))) {
            self.selected = Some(r.id());
        }
    }

    pub fn select_key(&mut self, k: &str) {
        self.selected = Some(RowId::Node(k.to_string()));
    }

    pub fn parent_of(&self, k: &str) -> Option<Key> {
        self.nodes.iter().find(|(_, n)| n.children.iter().any(|c| c == k)).map(|(pk, _)| pk.clone())
    }

    /// Stores loaded children for `k`, keeping existing child nodes (and their expansion state).
    pub fn set_children(&mut self, k: &str, list: ChildList) {
        let limit = self.child_limit;
        let mut keys = Vec::with_capacity(list.children.len() + list.referrals.len());
        for c in list.children {
            let ck = key_of(&c.dn);
            let node =
                self.nodes.entry(ck.clone()).or_insert_with(|| Node::new(&c.dn, display_rdn(&c.dn), c.kind, limit));
            node.kind = c.kind;
            node.has_children = c.has_children;
            keys.push(ck);
        }
        for url in list.referrals {
            let rk = format!("ref:{url}");
            let mut n = Node::new(&url, url.clone(), EntryKind::Referral, limit);
            n.referral = Some(url);
            n.load = Load::Loaded;
            self.nodes.insert(rk.clone(), n);
            keys.push(rk);
        }
        if let Some(n) = self.nodes.get_mut(k) {
            n.children = keys;
            n.truncated = list.truncated;
            n.load = Load::Loaded;
        }
    }

    /// Ensures `child_dn` appears under `parent` (used when revealing an entry that was beyond
    /// the loaded page or hidden by a filter).
    pub fn ensure_child(&mut self, parent: &str, child_dn: &str) -> Key {
        let ck = key_of(child_dn);
        let limit = self.child_limit;
        self.nodes
            .entry(ck.clone())
            .or_insert_with(|| Node::new(child_dn, display_rdn(child_dn), EntryKind::Other, limit));
        if let Some(p) = self.nodes.get_mut(parent)
            && !p.children.contains(&ck)
        {
            p.children.push(ck.clone());
        }
        ck
    }

    /// The root under which `dn` lies (longest match).
    pub fn root_for(&self, dn: &str) -> Option<Key> {
        self.roots
            .iter()
            .filter(|r| self.nodes.get(*r).is_some_and(|n| model::is_under(dn, &n.dn)))
            .max_by_key(|r| r.len())
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::model::Child;

    fn child(dn: &str, kind: EntryKind) -> Child {
        Child { dn: dn.into(), kind, has_children: None }
    }

    fn tree() -> Tree {
        let mut t = Tree::new(&["dc=ex,dc=org".into(), "cn=config".into()], 2);
        let root = key_of("dc=ex,dc=org");
        t.get_mut(&root).unwrap().expanded = true;
        t.set_children(
            &root,
            ChildList {
                children: vec![
                    child("ou=people,dc=ex,dc=org", EntryKind::OrgUnit),
                    child("ou=groups,dc=ex,dc=org", EntryKind::OrgUnit),
                ],
                referrals: vec![],
                truncated: true,
            },
        );
        t
    }

    #[test]
    fn display_rdn_unescapes() {
        assert_eq!(display_rdn(r"cn=Doe\2C Jane,ou=x"), "cn=Doe, Jane");
        assert_eq!(display_rdn(r"CN=Doe\, Jane,OU=x"), "CN=Doe, Jane");
        assert_eq!(display_rdn("cn=a+uid=b,dc=x"), "cn=a+uid=b");
    }

    #[test]
    fn rows_and_more() {
        let t = tree();
        let rows = t.rows();
        assert_eq!(rows.len(), 5); // root, 2 children, more, second root
        assert!(matches!(rows[3], Row::More { shown: 2, .. }));
        assert!(matches!(&rows[4], Row::Node { key, depth: 0 } if key == "cn=config"));
    }

    #[test]
    fn loading_and_empty_status() {
        let mut t = tree();
        let k = key_of("ou=people,dc=ex,dc=org");
        t.get_mut(&k).unwrap().expanded = true;
        t.get_mut(&k).unwrap().load = Load::Loading(1);
        assert!(t.rows().iter().any(|r| matches!(r, Row::Status { text, .. } if text == "loading…")));
        t.set_children(&k, ChildList::default());
        assert!(t.rows().iter().any(|r| matches!(r, Row::Status { text, .. } if text == "(no children)")));
    }

    #[test]
    fn reload_keeps_expansion() {
        let mut t = tree();
        let people = key_of("ou=people,dc=ex,dc=org");
        t.get_mut(&people).unwrap().expanded = true;
        let root = key_of("dc=ex,dc=org");
        t.set_children(
            &root,
            ChildList { children: vec![child("OU=People,DC=ex,DC=org", EntryKind::OrgUnit)], ..Default::default() },
        );
        assert!(t.get(&people).unwrap().expanded);
        assert_eq!(t.get(&root).unwrap().children, vec![people]);
    }

    #[test]
    fn ensure_child_and_root_for() {
        let mut t = tree();
        let root = key_of("dc=ex,dc=org");
        let k = t.ensure_child(&root, "ou=hidden,dc=ex,dc=org");
        assert!(t.get(&root).unwrap().children.contains(&k));
        assert_eq!(t.root_for("uid=a,ou=hidden,dc=ex,dc=org"), Some(root.clone()));
        assert_eq!(t.parent_of(&k), Some(root));
        assert_eq!(t.root_for("dc=other"), None);
    }

    #[test]
    fn selection_survives_row_changes() {
        let mut t = tree();
        let rows = t.rows();
        t.select_index(&rows, 2);
        let groups = key_of("ou=groups,dc=ex,dc=org");
        assert_eq!(t.selected_key(), Some(&groups));
        t.get_mut(&key_of("ou=people,dc=ex,dc=org")).unwrap().expanded = true;
        t.get_mut(&key_of("ou=people,dc=ex,dc=org")).unwrap().load = Load::Loading(3);
        let rows = t.rows();
        assert_eq!(t.selected_index(&rows), 3);
    }
}
