//! Data types passed from the LDAP worker to the UI, and DN helpers.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
    pub values: Vec<Value>,
    pub operational: bool,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub dn: String,
    /// Sorted: `objectClass` first, then user attributes alphabetically, then operational ones.
    pub attrs: Vec<Attribute>,
}

impl Entry {
    pub fn from_maps(dn: String, text: HashMap<String, Vec<String>>, bin: HashMap<String, Vec<Vec<u8>>>) -> Entry {
        let mut attrs: Vec<Attribute> = text
            .into_iter()
            .map(|(name, vals)| Attribute {
                operational: is_operational(&name),
                values: vals
                    .into_iter()
                    .map(|v| if is_binary_attr(&name) { Value::Binary(v.into_bytes()) } else { Value::Text(v) })
                    .collect(),
                name,
            })
            .chain(bin.into_iter().map(|(name, vals)| Attribute {
                operational: is_operational(&name),
                values: vals.into_iter().map(Value::Binary).collect(),
                name,
            }))
            .collect();
        sort_attrs(&mut attrs);
        Entry { dn, attrs }
    }

    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.name.eq_ignore_ascii_case(name))
    }

    pub fn first_text(&self, name: &str) -> Option<&str> {
        self.get(name)?.values.iter().find_map(|v| match v {
            Value::Text(s) => Some(s.as_str()),
            Value::Binary(_) => None,
        })
    }

    pub fn texts(&self, name: &str) -> Vec<&str> {
        self.get(name)
            .map(|a| {
                a.values
                    .iter()
                    .filter_map(|v| match v {
                        Value::Text(s) => Some(s.as_str()),
                        Value::Binary(_) => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn object_classes(&self) -> Vec<String> {
        self.texts("objectClass").iter().map(|s| s.to_ascii_lowercase()).collect()
    }

    pub fn kind(&self) -> EntryKind {
        EntryKind::from_object_classes(&self.object_classes())
    }
}

pub fn sort_attrs(attrs: &mut [Attribute]) {
    attrs.sort_by(|a, b| {
        let key =
            |x: &Attribute| (!x.name.eq_ignore_ascii_case("objectClass"), x.operational, x.name.to_ascii_lowercase());
        key(a).cmp(&key(b))
    });
}

/// Attributes that are always binary even when the bytes happen to be valid UTF-8.
pub fn is_binary_attr(name: &str) -> bool {
    const BIN: &[&str] = &[
        "objectguid",
        "objectsid",
        "tokengroups",
        "sidhistory",
        "jpegphoto",
        "thumbnailphoto",
        "usercertificate",
        "usercertificate;binary",
        "cacertificate",
        "cacertificate;binary",
        "msexchmailboxguid",
        "msexchmailboxsecuritydescriptor",
        "ntsecuritydescriptor",
        "logonhours",
        "msds-generationid",
        "msds-allowedtoactonbehalfofotheridentity",
        "msds-managedpasswordid",
        "replpropertymetadata",
        "replupToDateVector",
        "dsasignature",
        "schemaidguid",
        "attributesecurityguid",
        "mS-DS-ConsistencyGuid",
    ];
    let n = name.to_ascii_lowercase();
    let n = n.split(";range=").next().unwrap_or(&n);
    BIN.iter().any(|b| b.eq_ignore_ascii_case(n))
}

/// Best-effort classification of operational attributes (shown only when toggled on).
/// `memberOf` is operational in OpenLDAP but is treated as a user attribute here,
/// because following it is a core feature.
pub fn is_operational(name: &str) -> bool {
    const OPS: &[&str] = &[
        "createtimestamp",
        "modifytimestamp",
        "creatorsname",
        "modifiersname",
        "entryuuid",
        "entrydn",
        "entrycsn",
        "structuralobjectclass",
        "subschemasubentry",
        "hassubordinates",
        "numsubordinates",
        "pwdchangedtime",
        "pwdhistory",
        "pwdfailuretime",
        "pwdaccountlockedtime",
        "contextcsn",
        "governingstructurerule",
        "entryttl",
        "nsuniqueid",
        "ds-sync-hist",
        // AD bookkeeping
        "usnchanged",
        "usncreated",
        "dscorepropagationdata",
        "instancetype",
        "replpropertymetadata",
        "replupToDateVector",
        "objectcategory",
        "ntsecuritydescriptor",
        "iscriticalsystemobject",
        "systemflags",
        "showinadvancedviewonly",
        "msds-replattributemetadata",
        "msds-replvaluemetadata",
        "wellknownobjects",
        "otherwellknownobjects",
    ];
    OPS.iter().any(|o| o.eq_ignore_ascii_case(name))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Domain,
    OrgUnit,
    Container,
    User,
    Computer,
    Group,
    Gpo,
    Builtin,
    Referral,
    Other,
}

impl EntryKind {
    pub fn from_object_classes(ocs: &[String]) -> EntryKind {
        let has = |c: &str| ocs.iter().any(|o| o.eq_ignore_ascii_case(c));
        if has("computer") {
            EntryKind::Computer
        } else if has("user")
            || has("person")
            || has("inetorgperson")
            || has("posixaccount")
            || has("organizationalperson")
        {
            EntryKind::User
        } else if has("group")
            || has("groupofnames")
            || has("groupofuniquenames")
            || has("posixgroup")
            || has("groupofentries")
        {
            EntryKind::Group
        } else if has("grouppolicycontainer") {
            EntryKind::Gpo
        } else if has("builtindomain") {
            EntryKind::Builtin
        } else if has("domaindns") || has("domain") || has("dcobject") || has("organization") {
            EntryKind::Domain
        } else if has("organizationalunit") {
            EntryKind::OrgUnit
        } else if has("container")
            || has("configuration")
            || has("dmd")
            || has("dnszone")
            || has("olcglobal")
            || has("monitorserver")
            || has("lostandfound")
            || has("msds-quotacontainer")
            || has("infrastructureupdate")
        {
            EntryKind::Container
        } else if has("referral") {
            EntryKind::Referral
        } else {
            EntryKind::Other
        }
    }

    /// Whether the node is likely to have children. Leaf kinds can still be expanded on demand.
    pub fn likely_container(self) -> bool {
        matches!(
            self,
            EntryKind::Domain | EntryKind::OrgUnit | EntryKind::Container | EntryKind::Builtin | EntryKind::Other
        )
    }

    /// Order used when sorting siblings: containers first.
    pub fn sort_rank(self) -> u8 {
        match self {
            EntryKind::Domain | EntryKind::OrgUnit | EntryKind::Container | EntryKind::Builtin => 0,
            _ => 1,
        }
    }
}

/// A child entry in the tree.
#[derive(Debug, Clone)]
pub struct Child {
    pub dn: String,
    pub kind: EntryKind,
    /// From `hasSubordinates` when the server provides it.
    pub has_children: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ChildList {
    pub children: Vec<Child>,
    pub referrals: Vec<String>,
    /// More children exist beyond the requested limit.
    pub truncated: bool,
}

/// A search result / member list row.
#[derive(Debug, Clone)]
pub struct Hit {
    pub dn: String,
    pub kind: EntryKind,
    pub name: String,
    pub detail: String,
    /// Free-form tag, e.g. "primary" or "nested".
    pub tag: Option<String>,
    /// Every attribute the search returned, keyed by lower-cased name (range suffix stripped).
    pub values: HashMap<String, Vec<Value>>,
    /// Attributes whose values are incomplete because the server returned them in ranges.
    pub partial: Vec<String>,
}

impl Hit {
    pub fn bare(dn: &str, kind: EntryKind, name: String, detail: String) -> Hit {
        Hit { dn: dn.to_string(), kind, name, detail, tag: None, values: HashMap::new(), partial: Vec::new() }
    }

    pub fn values(&self, attr: &str) -> &[Value] {
        self.values.get(&attr.to_ascii_lowercase()).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn is_partial(&self, attr: &str) -> bool {
        self.partial.iter().any(|p| p.eq_ignore_ascii_case(attr))
    }
}

#[derive(Debug, Clone, Default)]
pub struct HitList {
    pub hits: Vec<Hit>,
    pub referrals: Vec<String>,
    pub truncated: bool,
    pub warning: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// DN helpers (RFC 4514 string form)

/// Splits a DN into its RDN strings, honouring backslash escapes and quoted values.
pub fn split_dn(dn: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = dn.chars();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ',' | ';' if !quoted => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out.retain(|s| !s.is_empty());
    out
}

pub fn rdn(dn: &str) -> String {
    split_dn(dn).into_iter().next().unwrap_or_default()
}

/// The unescaped value of the first RDN, e.g. `Jane, Doe` for `CN=Jane\, Doe,OU=x`.
pub fn rdn_value(dn: &str) -> String {
    let r = rdn(dn);
    let v = r.split_once('=').map(|(_, v)| v).unwrap_or(&r).trim();
    unescape_dn_value(v)
}

pub fn unescape_dn_value(v: &str) -> String {
    let v = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(v);
    let mut bytes = Vec::with_capacity(v.len());
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit()
                && let Ok(byte) = u8::from_str_radix(&v[i + 1..i + 3], 16)
            {
                bytes.push(byte);
                i += 3;
                continue;
            }
            bytes.push(b[i + 1]);
            i += 2;
        } else {
            bytes.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn parent_dn(dn: &str) -> Option<String> {
    let parts = split_dn(dn);
    (parts.len() > 1).then(|| parts[1..].join(","))
}

/// Canonical form for comparisons: lowercased, whitespace around `=` and separators removed.
pub fn normalize_dn(dn: &str) -> String {
    split_dn(dn)
        .iter()
        .map(|r| {
            r.split('+')
                .map(|ava| match ava.split_once('=') {
                    Some((a, v)) => format!(
                        "{}={}",
                        a.trim().to_ascii_lowercase(),
                        canonical_escape(&unescape_dn_value(v.trim()).to_lowercase())
                    ),
                    None => ava.trim().to_lowercase(),
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Re-escapes an attribute value in one canonical way, so `\2C` and `\,` compare equal.
fn canonical_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (i, c) in v.chars().enumerate() {
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=') || (i == 0 && matches!(c, '#' | ' ')) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn dn_eq(a: &str, b: &str) -> bool {
    normalize_dn(a) == normalize_dn(b)
}

/// True if `dn` equals `base` or lies beneath it.
pub fn is_under(dn: &str, base: &str) -> bool {
    let d = split_dn(&normalize_dn(dn));
    let b = split_dn(&normalize_dn(base));
    if b.is_empty() || d.len() < b.len() {
        return false;
    }
    d[d.len() - b.len()..] == b[..]
}

/// Ancestors of `dn` from `base` (inclusive) down to `dn`'s parent.
/// Returns `None` if `dn` is not under `base`.
pub fn ancestors_from(dn: &str, base: &str) -> Option<Vec<String>> {
    if !is_under(dn, base) {
        return None;
    }
    let parts = split_dn(dn);
    let base_len = split_dn(base).len();
    let mut out = Vec::new();
    for keep in base_len..parts.len() {
        out.push(parts[parts.len() - keep..].join(","));
    }
    Some(out)
}

/// Rough check that a string looks like a DN (`attr=value[,attr=value]*`).
pub fn looks_like_dn(s: &str) -> bool {
    let parts = split_dn(s);
    !parts.is_empty()
        && parts.iter().all(|p| {
            p.split_once('=').is_some_and(|(a, _)| {
                let a = a.trim();
                !a.is_empty()
                    && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                    && a.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_with_escapes() {
        assert_eq!(
            split_dn(r"CN=Doe\, Jane,OU=Staff,DC=example,DC=local"),
            vec![r"CN=Doe\, Jane", "OU=Staff", "DC=example", "DC=local"]
        );
        assert_eq!(split_dn(r#"cn="a,b",dc=x"#), vec![r#"cn="a,b""#, "dc=x"]);
        assert!(split_dn("").is_empty());
    }

    #[test]
    fn rdn_and_parent() {
        let dn = r"CN=Doe\, Jane,OU=Staff,DC=example,DC=local";
        assert_eq!(rdn(dn), r"CN=Doe\, Jane");
        assert_eq!(rdn_value(dn), "Doe, Jane");
        assert_eq!(parent_dn(dn).unwrap(), "OU=Staff,DC=example,DC=local");
        assert_eq!(parent_dn("DC=local"), None);
    }

    #[test]
    fn unescapes_hex() {
        assert_eq!(unescape_dn_value(r"caf\C3\A9"), "café");
        assert_eq!(unescape_dn_value(r"\23hash"), "#hash");
    }

    #[test]
    fn normalizes_case_and_spaces() {
        assert!(dn_eq("CN=Jane, OU=Staff ,DC=Example", "cn=jane,ou=staff,dc=example"));
        assert!(dn_eq("cn = a , dc=b", "CN=A,DC=B"));
        assert!(!dn_eq("cn=a,dc=b", "cn=a,dc=c"));
        assert!(dn_eq(r"cn=Doe\, Jane,dc=x", r"cn=Doe\2C Jane,dc=x"));
        assert!(dn_eq(r#"cn="Doe, Jane",dc=x"#, r"cn=Doe\2c Jane,dc=x"));
        assert!(is_under(r"uid=a,cn=Doe\2C Jane,dc=x", r"cn=Doe\, Jane,dc=x"));
    }

    #[test]
    fn under_and_ancestors() {
        let base = "DC=example,DC=local";
        let dn = "CN=Jane,OU=Staff,DC=example,DC=local";
        assert!(is_under(dn, base));
        assert!(is_under(base, base));
        assert!(!is_under("DC=other,DC=local", base));
        assert!(!is_under("DC=local", base));
        assert_eq!(
            ancestors_from(dn, base).unwrap(),
            vec!["DC=example,DC=local".to_string(), "OU=Staff,DC=example,DC=local".to_string()]
        );
        assert_eq!(ancestors_from(base, base).unwrap(), Vec::<String>::new());
        assert!(ancestors_from("cn=x,dc=y", base).is_none());
    }

    #[test]
    fn dn_detection() {
        assert!(looks_like_dn("CN=Jane,OU=Staff,DC=example"));
        assert!(looks_like_dn("uid=bob,ou=people,dc=x"));
        assert!(looks_like_dn("1.2.3=foo"));
        assert!(!looks_like_dn("hello world"));
        assert!(!looks_like_dn("a=b, c"));
        assert!(!looks_like_dn(""));
    }

    #[test]
    fn kinds() {
        let k = |v: &[&str]| EntryKind::from_object_classes(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(k(&["top", "person", "organizationalPerson", "user"]), EntryKind::User);
        assert_eq!(k(&["top", "person", "organizationalPerson", "user", "computer"]), EntryKind::Computer);
        assert_eq!(k(&["top", "group"]), EntryKind::Group);
        assert_eq!(k(&["groupOfUniqueNames"]), EntryKind::Group);
        assert_eq!(k(&["top", "organizationalUnit"]), EntryKind::OrgUnit);
        assert_eq!(k(&["top", "domain", "domainDNS"]), EntryKind::Domain);
        assert_eq!(k(&["top", "container"]), EntryKind::Container);
        assert_eq!(k(&["top", "groupPolicyContainer", "container"]), EntryKind::Gpo);
        assert_eq!(k(&["inetOrgPerson", "posixAccount"]), EntryKind::User);
    }

    #[test]
    fn entry_sorting_and_binary() {
        let mut text = HashMap::new();
        text.insert("mail".to_string(), vec!["a@b".to_string()]);
        text.insert("objectClass".to_string(), vec!["top".to_string()]);
        text.insert("cn".to_string(), vec!["a".to_string()]);
        text.insert("whenCreated".to_string(), vec!["x".to_string()]);
        text.insert("createTimestamp".to_string(), vec!["x".to_string()]);
        text.insert("objectGUID".to_string(), vec!["ascii-ish".to_string()]);
        let e = Entry::from_maps("cn=a".into(), text, HashMap::new());
        let names: Vec<_> = e.attrs.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["objectClass", "cn", "mail", "objectGUID", "whenCreated", "createTimestamp"]);
        assert!(matches!(e.get("objectguid").unwrap().values[0], Value::Binary(_)));
    }
}
