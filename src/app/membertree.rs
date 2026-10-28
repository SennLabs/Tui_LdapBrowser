//! Lazy membership tree for the members / memberOf views (plan section 5.6.8).
//!
//! `Members` walks down from a group to its members; `MemberOf` walks up from an entry to the
//! groups it belongs to. Each expanded node costs one request. A node that already appears on
//! the path from the root is shown as a cycle and cannot be expanded.

use std::collections::HashMap;

use crate::ldap::model::{self, EntryKind, Hit};
use crate::ldap::worker::RequestId;

pub const DEPTH_LIMIT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Members,
    MemberOf,
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
    pub hit: Hit,
    pub expanded: bool,
    pub load: Load,
    pub children: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Row {
    Node { key: String, depth: usize, cycle: bool, at_limit: bool },
    Status { depth: usize, text: String, error: bool },
}

#[derive(Debug, Clone)]
pub struct MemberTree {
    pub direction: Direction,
    pub root: String,
    pub nodes: HashMap<String, Node>,
    /// Selected display row.
    pub selected: usize,
}

fn key_of(dn: &str) -> String {
    model::normalize_dn(dn)
}

impl MemberTree {
    /// Builds a tree whose root is already expanded with `children` (the flat list on screen).
    pub fn new(direction: Direction, root: Hit, children: Vec<Hit>) -> MemberTree {
        let root_key = key_of(&root.dn);
        let mut nodes = HashMap::new();
        nodes.insert(root_key.clone(), Node { hit: root, expanded: true, load: Load::Loaded, children: vec![] });
        let mut t = MemberTree { direction, root: root_key.clone(), nodes, selected: 0 };
        t.set_children(&root_key, children);
        t
    }

    pub fn get(&self, key: &str) -> Option<&Node> {
        self.nodes.get(key)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Node> {
        self.nodes.get_mut(key)
    }

    /// Whether a node can be expanded at all (ignoring cycles and the depth limit).
    pub fn expandable(&self, node: &Node) -> bool {
        match self.direction {
            Direction::Members => node.hit.kind == EntryKind::Group,
            Direction::MemberOf => !node.hit.dn.is_empty(),
        }
    }

    /// Stores a node's children. Groups are listed first so the expandable rows sit together.
    pub fn set_children(&mut self, key: &str, mut hits: Vec<Hit>) {
        hits.sort_by_key(|h| h.kind != EntryKind::Group);
        let mut keys = Vec::with_capacity(hits.len());
        for (i, h) in hits.into_iter().enumerate() {
            // Rows without a DN (e.g. unresolved memberUid) get a unique synthetic key.
            let k = if h.dn.is_empty() { format!("{key}#{i}") } else { key_of(&h.dn) };
            let node = self.nodes.entry(k.clone()).or_insert_with(|| Node {
                hit: h.clone(),
                expanded: false,
                load: Load::NotLoaded,
                children: vec![],
            });
            if node.hit.tag.is_none() {
                node.hit.tag = h.tag;
            }
            keys.push(k);
        }
        if let Some(n) = self.nodes.get_mut(key) {
            n.children = keys;
            n.load = Load::Loaded;
            n.expanded = true;
        }
    }

    pub fn set_failed(&mut self, key: &str, why: String) {
        if let Some(n) = self.nodes.get_mut(key) {
            n.load = Load::Failed(why);
        }
    }

    pub fn rows(&self) -> Vec<Row> {
        let mut out = Vec::new();
        let mut path = Vec::new();
        self.push_rows(&self.root, 0, &mut path, &mut out);
        out
    }

    fn push_rows(&self, key: &str, depth: usize, path: &mut Vec<String>, out: &mut Vec<Row>) {
        let Some(n) = self.nodes.get(key) else { return };
        let cycle = path.iter().any(|p| p == key);
        let at_limit = depth >= DEPTH_LIMIT;
        out.push(Row::Node { key: key.to_string(), depth, cycle, at_limit });
        if cycle || at_limit || !n.expanded {
            return;
        }
        let d = depth + 1;
        match &n.load {
            Load::Loading(_) => {
                out.push(Row::Status { depth: d, text: "loading…".into(), error: false });
                return;
            }
            Load::Failed(e) => {
                out.push(Row::Status { depth: d, text: e.clone(), error: true });
                return;
            }
            Load::NotLoaded => return,
            Load::Loaded if n.children.is_empty() => {
                let text = match self.direction {
                    Direction::Members => "(no members)",
                    Direction::MemberOf => "(not a member of any group)",
                };
                out.push(Row::Status { depth: d, text: text.into(), error: false });
                return;
            }
            Load::Loaded => {}
        }
        path.push(key.to_string());
        for c in &n.children {
            self.push_rows(c, d, path, out);
        }
        path.pop();
    }

    pub fn selected_row(&self) -> Option<Row> {
        self.rows().get(self.selected).cloned()
    }

    pub fn selected_node(&self) -> Option<&Node> {
        match self.selected_row()? {
            Row::Node { key, .. } => self.nodes.get(&key),
            Row::Status { .. } => None,
        }
    }

    pub fn selected_key(&self) -> Option<String> {
        match self.selected_row()? {
            Row::Node { key, .. } => Some(key),
            Row::Status { .. } => None,
        }
    }

    /// Selects the row holding `key`, if it is visible.
    pub fn select_key(&mut self, key: &str) {
        if let Some(i) = self.rows().iter().position(|r| matches!(r, Row::Node { key: k, .. } if k == key)) {
            self.selected = i;
        }
    }

    /// The visible parent of the selected row.
    pub fn parent_of_selected(&self) -> Option<String> {
        let rows = self.rows();
        let depth = match rows.get(self.selected)? {
            Row::Node { depth, .. } | Row::Status { depth, .. } => *depth,
        };
        rows[..self.selected].iter().rev().find_map(|r| match r {
            Row::Node { key, depth: d, .. } if *d + 1 == depth => Some(key.clone()),
            _ => None,
        })
    }

    pub fn clamp(&mut self) {
        let n = self.rows().len();
        self.selected = self.selected.min(n.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(dn: &str, kind: EntryKind) -> Hit {
        Hit::bare(dn, kind, model::rdn_value(dn), String::new())
    }
    fn group(dn: &str) -> Hit {
        hit(dn, EntryKind::Group)
    }

    #[test]
    fn expands_lazily_and_marks_cycles() {
        // everyone contains staff; staff contains everyone (a cycle) and alice.
        let mut t = MemberTree::new(
            Direction::Members,
            group("cn=everyone,ou=g,dc=x"),
            vec![group("cn=staff,ou=g,dc=x"), hit("uid=carol,ou=p,dc=x", EntryKind::User)],
        );
        assert_eq!(t.rows().len(), 3);
        let staff = key_of("cn=staff,ou=g,dc=x");
        assert!(t.expandable(t.get(&staff).unwrap()));
        assert!(!t.expandable(t.get(&key_of("uid=carol,ou=p,dc=x")).unwrap()));
        t.get_mut(&staff).unwrap().load = Load::Loading(7);
        t.get_mut(&staff).unwrap().expanded = true;
        assert!(t.rows().iter().any(|r| matches!(r, Row::Status { text, .. } if text == "loading…")));
        t.set_children(&staff, vec![group("CN=Everyone,OU=g,DC=x"), hit("uid=alice,ou=p,dc=x", EntryKind::User)]);
        let rows = t.rows();
        // root, staff, everyone(cycle), alice, carol
        assert_eq!(rows.len(), 5, "{rows:?}");
        assert!(matches!(&rows[2], Row::Node { cycle: true, depth: 2, .. }));
        // The cycle node is the same node as the root (same normalized key), but is never recursed into.
        t.selected = 2;
        assert_eq!(t.selected_key().as_deref(), Some(key_of("cn=everyone,ou=g,dc=x").as_str()));
        assert_eq!(t.parent_of_selected().as_deref(), Some(staff.as_str()));
        // Collapsing staff hides its children again.
        t.get_mut(&staff).unwrap().expanded = false;
        assert_eq!(t.rows().len(), 3);
        t.selected = 4;
        t.clamp();
        assert_eq!(t.selected, 2);
    }

    #[test]
    fn member_of_direction_expands_groups_only_upwards_and_honours_depth_limit() {
        let mut t = MemberTree::new(Direction::MemberOf, hit("uid=bob,ou=p,dc=x", EntryKind::User), vec![]);
        assert!(t.rows().iter().any(|r| matches!(r, Row::Status { text, .. } if text.contains("not a member"))));
        // Build a chain g0 ∈ g1 ∈ … ∈ g12 and expand it all.
        let mut parent = t.root.clone();
        for i in 0..12 {
            let dn = format!("cn=g{i},ou=g,dc=x");
            t.set_children(&parent, vec![group(&dn)]);
            parent = key_of(&dn);
        }
        let rows = t.rows();
        let last = rows.last().unwrap();
        assert!(matches!(last, Row::Node { at_limit: true, depth: DEPTH_LIMIT, .. }), "{last:?}");
        assert_eq!(rows.len(), DEPTH_LIMIT + 1);
    }

    #[test]
    fn rows_without_dn_get_unique_keys() {
        let t = MemberTree::new(
            Direction::Members,
            group("cn=posix,ou=g,dc=x"),
            vec![
                Hit::bare("", EntryKind::Other, "ghost1".into(), String::new()),
                Hit::bare("", EntryKind::Other, "ghost2".into(), String::new()),
            ],
        );
        assert_eq!(t.rows().len(), 3);
    }
}
