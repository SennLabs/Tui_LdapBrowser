//! Side-by-side comparison of two entries (`d` to mark, `D` to diff).
//!
//! The comparison is purely client-side: both entries are already loaded. Multi-valued
//! attributes are compared as sets, with shared values listed first so that they line up.

use ratatui::widgets::TableState;

use super::attr_matches;
use super::input::TextInput;
use crate::ldap::flavor::Flavor;
use crate::ldap::model::{self, Entry, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowState {
    Equal,
    Differs,
    OnlyLeft,
    OnlyRight,
}

/// One attribute present in either entry.
#[derive(Debug, Clone)]
pub struct DiffAttr {
    pub name: String,
    pub operational: bool,
    /// Expected to differ between any two entries (GUIDs, timestamps, …); grouped separately.
    pub identity: bool,
    pub state: RowState,
    /// Values aligned so that `left[i]` and `right[i]` are equal for `i < shared`.
    pub left: Vec<Value>,
    pub right: Vec<Value>,
    pub shared: usize,
}

impl DiffAttr {
    /// Number of table rows this attribute occupies.
    pub fn row_count(&self) -> usize {
        self.left.len().max(self.right.len()).max(1)
    }
}

/// Attributes that differ between any two entries and would otherwise drown out real differences.
pub fn identity_attrs(flavor: Flavor) -> &'static [&'static str] {
    const AD: &[&str] = &[
        "objectguid",
        "objectsid",
        "distinguishedname",
        "name",
        "cn",
        "usnchanged",
        "usncreated",
        "whencreated",
        "whenchanged",
        "dscorepropagationdata",
        "samaccountname",
        "userprincipalname",
        "objectcategory",
    ];
    const LDAP: &[&str] = &[
        "entryuuid",
        "entrydn",
        "entrycsn",
        "createtimestamp",
        "modifytimestamp",
        "creatorsname",
        "modifiersname",
        "cn",
        "uid",
        "nsuniqueid",
        "uidnumber",
    ];
    match flavor {
        Flavor::Ad => AD,
        _ => LDAP,
    }
}

/// Computes the aligned attribute list for two entries, in entry-pane order.
pub fn diff_entries(left: &Entry, right: &Entry, flavor: Flavor) -> Vec<DiffAttr> {
    let identity = identity_attrs(flavor);
    let mut names: Vec<(String, bool)> = Vec::new();
    for a in left.attrs.iter().chain(right.attrs.iter()) {
        if !names.iter().any(|(n, _)| n.eq_ignore_ascii_case(&a.name)) {
            names.push((a.name.clone(), a.operational));
        }
    }
    let mut out: Vec<DiffAttr> = names
        .into_iter()
        .map(|(name, operational)| {
            let l = left.get(&name).map(|a| a.values.clone()).unwrap_or_default();
            let r = right.get(&name).map(|a| a.values.clone()).unwrap_or_default();
            let (lv, rv, shared) = align(l, r);
            let state = match (left.get(&name).is_some(), right.get(&name).is_some()) {
                (true, false) => RowState::OnlyLeft,
                (false, true) => RowState::OnlyRight,
                _ if shared == lv.len() && shared == rv.len() => RowState::Equal,
                _ => RowState::Differs,
            };
            let lname = name.to_ascii_lowercase();
            DiffAttr {
                identity: identity.contains(&lname.as_str()),
                name,
                operational,
                state,
                left: lv,
                right: rv,
                shared,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        let key =
            |x: &DiffAttr| (!x.name.eq_ignore_ascii_case("objectClass"), x.operational, x.name.to_ascii_lowercase());
        key(a).cmp(&key(b))
    });
    out
}

/// Orders two value lists so shared values come first (in `left`'s order), then the rest.
fn align(left: Vec<Value>, right: Vec<Value>) -> (Vec<Value>, Vec<Value>, usize) {
    let shared: Vec<Value> = left.iter().filter(|v| right.contains(v)).cloned().collect();
    let left_only: Vec<Value> = left.iter().filter(|v| !right.contains(v)).cloned().collect();
    let right_only: Vec<Value> = right.iter().filter(|v| !left.contains(v)).cloned().collect();
    let n = shared.len();
    let mut l = shared.clone();
    l.extend(left_only);
    let mut r = shared;
    r.extend(right_only);
    (l, r, n)
}

/// A row of the diff table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffRow {
    /// (attribute index, value index)
    Value(usize, usize),
    /// Collapsible heading for the identity attributes, with their count.
    IdentityHeader(usize),
}

pub struct DiffView {
    pub left: Entry,
    pub right: Entry,
    pub attrs: Vec<DiffAttr>,
    pub flavor: Flavor,
    pub state: TableState,
    /// `a`: show only differing attributes (default) or everything.
    pub only_differences: bool,
    pub show_operational: bool,
    pub show_identity: bool,
    /// Attribute-name filter (`:`), applied as the user types.
    pub filter: String,
    pub editing: Option<TextInput>,
    /// 0 = left (marked) side, 1 = right (current) side; used for follow and copy.
    pub side: usize,
}

impl DiffView {
    pub fn new(left: Entry, right: Entry, flavor: Flavor) -> DiffView {
        let attrs = diff_entries(&left, &right, flavor);
        let mut state = TableState::default();
        state.select(Some(0));
        DiffView {
            left,
            right,
            attrs,
            flavor,
            state,
            only_differences: true,
            show_operational: false,
            show_identity: false,
            filter: String::new(),
            editing: None,
            side: 1,
        }
    }

    pub fn set_left(&mut self, e: Entry) {
        self.left = e;
        self.recompute();
    }

    pub fn set_right(&mut self, e: Entry) {
        self.right = e;
        self.recompute();
    }

    fn recompute(&mut self) {
        self.attrs = diff_entries(&self.left, &self.right, self.flavor);
        self.clamp();
    }

    pub fn clamp(&mut self) {
        let len = self.rows().len();
        let sel = self.state.selected().unwrap_or(0);
        self.state.select((len > 0).then_some(sel.min(len - 1)));
    }

    fn shown(&self, a: &DiffAttr) -> bool {
        (self.show_operational || !a.operational)
            && (!self.only_differences || a.state != RowState::Equal)
            && attr_matches((!self.filter.is_empty()).then_some(self.filter.as_str()), &a.name)
    }

    pub fn rows(&self) -> Vec<DiffRow> {
        let mut rows = Vec::new();
        for (ai, a) in self.attrs.iter().enumerate() {
            if !a.identity && self.shown(a) {
                rows.extend((0..a.row_count()).map(|vi| DiffRow::Value(ai, vi)));
            }
        }
        let ident: Vec<usize> =
            self.attrs.iter().enumerate().filter(|(_, a)| a.identity && self.shown(a)).map(|(i, _)| i).collect();
        if !ident.is_empty() {
            rows.push(DiffRow::IdentityHeader(ident.len()));
            if self.show_identity {
                for ai in ident {
                    rows.extend((0..self.attrs[ai].row_count()).map(|vi| DiffRow::Value(ai, vi)));
                }
            }
        }
        rows
    }

    /// Counts of (differing, total) attributes, ignoring the filter and visibility toggles.
    pub fn counts(&self) -> (usize, usize) {
        let visible = self.attrs.iter().filter(|a| self.show_operational || !a.operational);
        let total = visible.clone().count();
        let differing = visible.filter(|a| a.state != RowState::Equal).count();
        (differing, total)
    }

    pub fn selected_row(&self) -> Option<DiffRow> {
        self.rows().get(self.state.selected()?).copied()
    }

    /// The value under the cursor on the focused side.
    pub fn selected_value(&self) -> Option<(&str, &Value)> {
        let DiffRow::Value(ai, vi) = self.selected_row()? else { return None };
        let a = &self.attrs[ai];
        let v = if self.side == 0 { a.left.get(vi) } else { a.right.get(vi) }?;
        Some((&a.name, v))
    }

    pub fn selected_dn(&self) -> Option<String> {
        let (name, v) = self.selected_value()?;
        match v {
            Value::Text(s) if super::is_followable(name, s) => Some(s.clone()),
            _ => None,
        }
    }

    pub fn side_dn(&self) -> &str {
        if self.side == 0 { &self.left.dn } else { &self.right.dn }
    }

    pub fn toggle_identity(&mut self) {
        self.show_identity = !self.show_identity;
        self.clamp();
    }

    pub fn set_filter(&mut self, text: &str) {
        self.filter = text.trim().to_string();
        self.state.select(Some(0));
        self.clamp();
    }

    pub fn title_rdns(&self) -> (String, String) {
        (model::rdn_value(&self.left.dn), model::rdn_value(&self.right.dn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::model::Attribute;

    fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> Entry {
        let mut attrs: Vec<Attribute> = attrs
            .iter()
            .map(|(n, vs)| Attribute {
                name: n.to_string(),
                values: vs.iter().map(|v| Value::Text(v.to_string())).collect(),
                operational: model::is_operational(n),
            })
            .collect();
        model::sort_attrs(&mut attrs);
        Entry { dn: dn.into(), attrs }
    }

    fn jane() -> Entry {
        entry(
            "CN=Jane,OU=Staff,DC=x",
            &[
                ("objectClass", &["top", "person", "user"]),
                ("cn", &["Jane"]),
                ("mail", &["jane@x"]),
                ("memberOf", &["CN=A,DC=x", "CN=B,DC=x"]),
                ("department", &["IT"]),
                ("uSNChanged", &["100"]),
                ("whenCreated", &["20240101000000.0Z"]),
            ],
        )
    }

    fn john() -> Entry {
        entry(
            "CN=John,OU=Staff,DC=x",
            &[
                ("objectClass", &["top", "person", "user"]),
                ("cn", &["John"]),
                ("mail", &["john@x"]),
                ("memberOf", &["CN=B,DC=x", "CN=C,DC=x"]),
                ("title", &["Boss"]),
                ("uSNChanged", &["200"]),
                ("whenCreated", &["20240202000000.0Z"]),
            ],
        )
    }

    fn find<'a>(d: &'a [DiffAttr], name: &str) -> &'a DiffAttr {
        d.iter().find(|a| a.name == name).unwrap()
    }

    #[test]
    fn states_and_alignment() {
        let d = diff_entries(&jane(), &john(), Flavor::Ad);
        assert_eq!(find(&d, "objectClass").state, RowState::Equal);
        assert_eq!(find(&d, "mail").state, RowState::Differs);
        assert_eq!(find(&d, "department").state, RowState::OnlyLeft);
        assert_eq!(find(&d, "title").state, RowState::OnlyRight);
        let m = find(&d, "memberOf");
        assert_eq!(m.state, RowState::Differs);
        assert_eq!(m.shared, 1);
        assert_eq!(m.left, vec![Value::Text("CN=B,DC=x".into()), Value::Text("CN=A,DC=x".into())]);
        assert_eq!(m.right, vec![Value::Text("CN=B,DC=x".into()), Value::Text("CN=C,DC=x".into())]);
        assert!(find(&d, "cn").identity && find(&d, "uSNChanged").identity && find(&d, "whenCreated").identity);
        assert!(!find(&d, "mail").identity);
        // objectClass first, then alphabetical user attributes, operational last.
        assert_eq!(d[0].name, "objectClass");
        assert_eq!(d.last().unwrap().name, "uSNChanged");
    }

    #[test]
    fn set_comparison_ignores_order() {
        let a = entry("cn=a", &[("memberOf", &["x", "y"])]);
        let b = entry("cn=b", &[("memberOf", &["y", "x"])]);
        let d = diff_entries(&a, &b, Flavor::OpenLdap);
        assert_eq!(find(&d, "memberOf").state, RowState::Equal);
    }

    #[test]
    fn rows_honour_toggles_and_filter() {
        let mut v = DiffView::new(jane(), john(), Flavor::Ad);
        // Differences only, identity collapsed, operational hidden: mail, memberOf(2), department, title + header.
        let rows = v.rows();
        assert_eq!(rows.len(), 6, "{rows:?}");
        assert_eq!(rows.last(), Some(&DiffRow::IdentityHeader(2)));
        v.toggle_identity();
        assert_eq!(v.rows().len(), 8);
        v.only_differences = false;
        assert!(v.rows().iter().any(|r| matches!(r, DiffRow::Value(ai, _) if v.attrs[*ai].name == "objectClass")));
        v.show_operational = true;
        v.toggle_identity();
        v.toggle_identity();
        assert_eq!(v.rows().last(), Some(&DiffRow::Value(v.attrs.len() - 1, 0)));
        v.set_filter("MAIL");
        let rows = v.rows();
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0], DiffRow::Value(ai, 0) if v.attrs[ai].name == "mail"));
        assert_eq!(v.counts(), (7, 8));
    }

    #[test]
    fn selected_value_follows_side() {
        let mut v = DiffView::new(jane(), john(), Flavor::Ad);
        v.set_filter("mail");
        assert_eq!(v.selected_value().map(|(_, x)| x.clone()), Some(Value::Text("john@x".into())));
        v.side = 0;
        assert_eq!(v.selected_value().map(|(_, x)| x.clone()), Some(Value::Text("jane@x".into())));
        assert_eq!(v.side_dn(), "CN=Jane,OU=Staff,DC=x");
        v.set_filter("memberOf");
        v.state.select(Some(1));
        assert_eq!(v.selected_dn().as_deref(), Some("CN=A,DC=x"));
    }
}
