//! Non-secret configuration: connection profiles loaded from `config.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Ldap,
    #[default]
    Ldaps,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Ldap => "ldap",
            Scheme::Ldaps => "ldaps",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Ldap => 389,
            Scheme::Ldaps => 636,
        }
    }
}

/// Directory server flavor as configured. `Auto` is resolved from the RootDSE at connect time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FlavorSetting {
    #[default]
    Auto,
    Ad,
    OpenLdap,
    Lldap,
}

/// A named filter offered in the search dialog's Saved tab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSearch {
    pub name: String,
    /// An LDAP filter; may contain `{q}`, which is replaced by escaped text asked for at run time.
    pub filter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// `"subtree"` (default), `"onelevel"` or `"base"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl SavedSearch {
    pub fn takes_text(&self) -> bool {
        self.filter.contains("{q}")
    }

    /// Index into [`crate::app::SCOPES`] for the configured scope name.
    pub fn scope_index(&self) -> usize {
        match self.scope.as_deref().map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("one" | "onelevel" | "one level" | "single") => 1,
            Some("base" | "object") => 2,
            _ => 0,
        }
    }

    fn validate(&self, what: &str) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("{what}: \"name\" must not be empty");
        }
        let probe = self.filter.replace("{q}", "x");
        if ldap3::parse_filter(&probe).is_err() {
            bail!("{what}: not a valid LDAP filter: {}", self.filter);
        }
        if let Some(s) = &self.scope
            && !matches!(
                s.to_ascii_lowercase().as_str(),
                "sub" | "subtree" | "one" | "onelevel" | "one level" | "single" | "base" | "object"
            )
        {
            bail!("{what}: \"scope\" must be subtree, onelevel or base");
        }
        Ok(())
    }
}

/// A pinned DN (`B` to add, `'` to open the list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bookmark {
    pub name: String,
    pub dn: String,
}

/// Per-result-kind column defaults (section 5.6.7). Each list names attributes or the virtual
/// columns `parent`, `members` and `kind`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnDefaults {
    pub users: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
    pub other: Option<Vec<String>>,
}

impl ColumnDefaults {
    pub fn get(&self, kind: &str) -> Option<&Vec<String>> {
        match kind {
            "users" => self.users.as_ref(),
            "groups" => self.groups.as_ref(),
            _ => self.other.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    /// Directory offered in the export dialog. `~` is expanded. Defaults to the home directory.
    pub dir: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultsConfig {
    #[serde(default)]
    pub columns: ColumnDefaults,
    /// Default sort: `"name"`, an attribute, or `"attr:desc"`.
    pub sort: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchOverrides {
    pub user_filter: Option<String>,
    pub group_filter: Option<String>,
    #[serde(default)]
    pub saved: Vec<SavedSearch>,
}

/// Top-level `search` object: saved searches shared by every profile.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSearch {
    #[serde(default)]
    pub saved: Vec<SavedSearch>,
}

fn default_timeout() -> u64 {
    10
}
fn default_page_size() -> i32 {
    500
}
fn default_size_limit() -> i32 {
    5000
}
fn default_child_limit() -> usize {
    1000
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Filled in from the map key after loading.
    #[serde(skip)]
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub scheme: Scheme,
    pub port: Option<u16>,
    #[serde(default)]
    pub flavor: FlavorSetting,
    pub base_dn: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    pub ca_cert: Option<PathBuf>,
    pub credentials: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_page_size")]
    pub page_size: i32,
    #[serde(default = "default_size_limit")]
    pub size_limit: i32,
    #[serde(default = "default_child_limit")]
    pub tree_child_limit: usize,
    #[serde(default = "default_true")]
    pub show_all_naming_contexts: bool,
    #[serde(default)]
    pub search: SearchOverrides,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    #[serde(default)]
    pub results: ResultsConfig,
    #[serde(default)]
    pub export: ExportConfig,
}

impl Profile {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.scheme.default_port())
    }

    pub fn url(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host) // bare IPv6 literal
        } else {
            self.host.clone()
        };
        format!("{}://{}:{}", self.scheme.as_str(), host, self.port())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    fn validate(&self) -> Result<()> {
        let field = |f: &str| format!("profile \"{}\", field \"{}\"", self.name, f);
        if self.host.trim().is_empty() {
            bail!("{}: must not be empty", field("host"));
        }
        if self.port == Some(0) {
            bail!("{}: must be between 1 and 65535", field("port"));
        }
        if self.insecure_skip_verify && self.scheme == Scheme::Ldap {
            bail!(
                "{}: only allowed with scheme \"ldaps\" (plain LDAP has no certificate to skip)",
                field("insecure_skip_verify")
            );
        }
        if self.ca_cert.is_some() && self.scheme == Scheme::Ldap {
            bail!("{}: only allowed with scheme \"ldaps\"", field("ca_cert"));
        }
        if let Some(ca) = &self.ca_cert
            && !ca.is_file()
        {
            bail!("{}: file not found: {}", field("ca_cert"), ca.display());
        }
        if self.timeout_secs == 0 {
            bail!("{}: must be at least 1", field("timeout_secs"));
        }
        if self.page_size <= 0 {
            bail!("{}: must be at least 1", field("page_size"));
        }
        if self.size_limit <= 0 {
            bail!("{}: must be at least 1", field("size_limit"));
        }
        if self.tree_child_limit == 0 {
            bail!("{}: must be at least 1", field("tree_child_limit"));
        }
        for (name, f) in
            [("search.user_filter", &self.search.user_filter), ("search.group_filter", &self.search.group_filter)]
        {
            if let Some(f) = f {
                let probe = f.replace("{q}", "x");
                if ldap3::parse_filter(&probe).is_err() {
                    bail!("{}: not a valid LDAP filter: {}", field(name), f);
                }
            }
        }
        if let Some(base) = &self.base_dn
            && base.trim().is_empty()
        {
            bail!("{}: must not be empty (omit it to auto-discover)", field("base_dn"));
        }
        for (i, s) in self.search.saved.iter().enumerate() {
            s.validate(&field(&format!("search.saved[{i}]")))?;
        }
        let column_ok = |c: &str| {
            matches!(c.to_ascii_lowercase().as_str(), "parent" | "members" | "kind")
                || crate::ldap::filter::valid_attribute(c)
        };
        for (kind, cols) in [
            ("users", &self.results.columns.users),
            ("groups", &self.results.columns.groups),
            ("other", &self.results.columns.other),
        ] {
            for c in cols.iter().flatten() {
                if !column_ok(c) {
                    bail!("{}: not an attribute name: {c:?}", field(&format!("results.columns.{kind}")));
                }
            }
        }
        if let Some(s) = &self.results.sort {
            let col = s.split(':').next().unwrap_or("").trim();
            if !(col.eq_ignore_ascii_case("name") || column_ok(col)) {
                bail!("{}: must be \"name\", an attribute, or \"attr:desc\"", field("results.sort"));
            }
        }
        for (i, b) in self.bookmarks.iter().enumerate() {
            if b.name.trim().is_empty() {
                bail!("{}: \"name\" must not be empty", field(&format!("bookmarks[{i}]")));
            }
            if !crate::ldap::model::looks_like_dn(&b.dn) {
                bail!("{}: \"dn\" is not a DN: {}", field(&format!("bookmarks[{i}]")), b.dn);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the config was loaded from; `None` for configs parsed from text (tests).
    #[serde(skip)]
    pub path: Option<PathBuf>,
    pub default_profile: Option<String>,
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub search: SharedSearch,
    /// Mouse capture (click, wheel, right-click menu). `--no-mouse` overrides it.
    #[serde(default = "default_true")]
    pub mouse: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("cannot read config file {}", path.display()))?;
        let mut cfg =
            Self::parse(&text, path.parent()).with_context(|| format!("invalid config file {}", path.display()))?;
        cfg.path = Some(path.to_path_buf());
        Ok(cfg)
    }

    /// Writes the saved searches and bookmarks back to the config file (section 5.6.9 of the plan).
    ///
    /// The file is re-read first so that every other field, and the key order, survive edits
    /// made outside the app since it started. Only `search.saved` (top level and per profile)
    /// and each profile's `bookmarks` are replaced. The write is atomic (temp file + rename) and
    /// keeps the original permission bits.
    pub fn persist(&self) -> Result<()> {
        let path = self.path.as_ref().context("config was not loaded from a file")?;
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot re-read {}", path.display()))?;
        let mut root: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("{} is no longer valid JSON", path.display()))?;
        let obj = root.as_object_mut().context("config root is not an object")?;
        set_list(obj, "search", "saved", &self.search.saved)?;
        let profiles = obj
            .entry("profiles")
            .or_insert_with(|| serde_json::Value::Object(Default::default()))
            .as_object_mut()
            .context("\"profiles\" is not an object")?;
        for (name, p) in &self.profiles {
            let Some(pobj) = profiles.get_mut(name).and_then(|v| v.as_object_mut()) else { continue };
            set_list(pobj, "search", "saved", &p.search.saved)?;
            if p.bookmarks.is_empty() {
                pobj.remove("bookmarks");
            } else {
                pobj.insert("bookmarks".into(), serde_json::to_value(&p.bookmarks)?);
            }
        }
        let mut out = serde_json::to_string_pretty(&root)?;
        out.push('\n');
        write_atomic(path, out.as_bytes())
    }

    /// Parses config text. Relative `ca_cert` paths are resolved against `base_dir`.
    pub fn parse(text: &str, base_dir: Option<&Path>) -> Result<Config> {
        let mut cfg: Config = serde_json::from_str(text)?;
        if cfg.profiles.is_empty() {
            bail!("\"profiles\" must contain at least one profile");
        }
        for (name, p) in cfg.profiles.iter_mut() {
            p.name = name.clone();
            if let (Some(ca), Some(dir)) = (&p.ca_cert, base_dir)
                && ca.is_relative()
            {
                p.ca_cert = Some(dir.join(ca));
            }
            p.validate()?;
        }
        if let Some(d) = &cfg.default_profile
            && !cfg.profiles.contains_key(d)
        {
            bail!("\"default_profile\" names unknown profile \"{d}\"");
        }
        Ok(cfg)
    }

    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    pub fn profile_mut(&mut self, name: &str) -> Option<&mut Profile> {
        self.profiles.get_mut(name)
    }

    pub fn profile_names(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }
}

/// Sets `obj[section][key]` to `items`, removing empty lists and then-empty sections.
fn set_list<T: Serialize>(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    section: &str,
    key: &str,
    items: &[T],
) -> Result<()> {
    if items.is_empty() {
        if let Some(sec) = obj.get_mut(section).and_then(|v| v.as_object_mut()) {
            sec.remove(key);
            if sec.is_empty() {
                obj.remove(section);
            }
        }
        return Ok(());
    }
    let sec = obj
        .entry(section)
        .or_insert_with(|| serde_json::Value::Object(Default::default()))
        .as_object_mut()
        .with_context(|| format!("\"{section}\" is not an object"))?;
    sec.insert(key.into(), serde_json::to_value(items)?);
    Ok(())
}

/// Writes via a temp file in the same directory, fsyncs, renames over the target and copies the
/// original permission bits.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|f| f.to_str()).unwrap_or("config.json"),
        std::process::id()
    ));
    let perms = std::fs::metadata(path).ok().map(|m| m.permissions());
    let result = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        if let Some(p) = perms {
            f.set_permissions(p)?;
        }
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("cannot write {}", path.display()))
}

pub fn project_dirs() -> Option<directories::ProjectDirs> {
    directories::ProjectDirs::from("", "", "ldaptui")
}

pub fn default_config_path() -> PathBuf {
    project_dirs().map(|d| d.config_dir().join("config.json")).unwrap_or_else(|| PathBuf::from("config.json"))
}

pub fn default_secrets_path() -> PathBuf {
    project_dirs().map(|d| d.config_dir().join("secrets.json")).unwrap_or_else(|| PathBuf::from("secrets.json"))
}

pub fn default_log_dir() -> PathBuf {
    default_state_dir()
}

/// `$XDG_STATE_HOME/ldaptui` (normally `~/.local/state/ldaptui`): logs and search history.
pub fn default_state_dir() -> PathBuf {
    project_dirs().and_then(|d| d.state_dir().map(Path::to_path_buf)).unwrap_or_else(std::env::temp_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_profile_gets_defaults() {
        let cfg = Config::parse(r#"{"profiles":{"a":{"host":"dc1"}}}"#, None).unwrap();
        let p = cfg.profile("a").unwrap();
        assert_eq!(p.name, "a");
        assert_eq!(p.scheme, Scheme::Ldaps);
        assert_eq!(p.port(), 636);
        assert_eq!(p.flavor, FlavorSetting::Auto);
        assert_eq!(p.url(), "ldaps://dc1:636");
        assert_eq!(p.page_size, 500);
        assert_eq!(p.size_limit, 5000);
        assert_eq!(p.tree_child_limit, 1000);
        assert!(p.show_all_naming_contexts);
        assert!(!p.insecure_skip_verify);
    }

    #[test]
    fn plain_ldap_default_port() {
        let cfg = Config::parse(r#"{"profiles":{"a":{"host":"h","scheme":"ldap"}}}"#, None).unwrap();
        assert_eq!(cfg.profile("a").unwrap().url(), "ldap://h:389");
    }

    #[test]
    fn ipv6_host_is_bracketed() {
        let cfg = Config::parse(r#"{"profiles":{"a":{"host":"::1","port":6360}}}"#, None).unwrap();
        assert_eq!(cfg.profile("a").unwrap().url(), "ldaps://[::1]:6360");
    }

    #[test]
    fn insecure_with_plain_ldap_is_rejected() {
        let err = Config::parse(r#"{"profiles":{"a":{"host":"h","scheme":"ldap","insecure_skip_verify":true}}}"#, None)
            .unwrap_err();
        assert!(err.to_string().contains("insecure_skip_verify"), "{err}");
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert!(Config::parse(r#"{"profiles":{"a":{"host":"h","prot":1}}}"#, None).is_err());
    }

    #[test]
    fn unknown_default_profile_is_rejected() {
        let err = Config::parse(r#"{"default_profile":"x","profiles":{"a":{"host":"h"}}}"#, None).unwrap_err();
        assert!(err.to_string().contains("unknown profile"));
    }

    #[test]
    fn bad_filter_override_is_rejected() {
        let err =
            Config::parse(r#"{"profiles":{"a":{"host":"h","search":{"user_filter":"(uid={q}"}}}}"#, None).unwrap_err();
        assert!(err.to_string().contains("search.user_filter"), "{err}");
    }

    #[test]
    fn flavors_parse() {
        for (s, f) in [
            ("ad", FlavorSetting::Ad),
            ("openldap", FlavorSetting::OpenLdap),
            ("lldap", FlavorSetting::Lldap),
            ("auto", FlavorSetting::Auto),
        ] {
            let cfg = Config::parse(&format!(r#"{{"profiles":{{"a":{{"host":"h","flavor":"{s}"}}}}}}"#), None).unwrap();
            assert_eq!(cfg.profile("a").unwrap().flavor, f);
        }
    }

    #[test]
    fn saved_searches_and_bookmarks_parse_and_validate() {
        let cfg = Config::parse(
            r#"{"search":{"saved":[{"name":"disabled","filter":"(userAccountControl:1.2.840.113556.1.4.803:=2)"}]},
                "profiles":{"a":{"host":"h","search":{"saved":[{"name":"by uid","filter":"(uid={q})","scope":"onelevel","base":"ou=people,dc=x"}]},
                "bookmarks":[{"name":"people","dn":"ou=people,dc=x"}]}}}"#,
            None,
        )
        .unwrap();
        assert_eq!(cfg.search.saved.len(), 1);
        let p = cfg.profile("a").unwrap();
        assert!(p.search.saved[0].takes_text());
        assert_eq!(p.search.saved[0].scope_index(), 1);
        assert!(!cfg.search.saved[0].takes_text());
        assert_eq!(p.bookmarks[0].dn, "ou=people,dc=x");
        let err = Config::parse(
            r#"{"profiles":{"a":{"host":"h","search":{"saved":[{"name":"x","filter":"(uid="}]}}}}"#,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("search.saved[0]"), "{err}");
        let err = Config::parse(r#"{"profiles":{"a":{"host":"h","bookmarks":[{"name":"x","dn":"nope"}]}}}"#, None)
            .unwrap_err();
        assert!(err.to_string().contains("bookmarks[0]"), "{err}");
    }

    #[test]
    fn persist_round_trip_preserves_other_fields_and_order() {
        let dir = std::env::temp_dir().join(format!("ldaptui-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let original = "{\n  \"default_profile\": \"b\",\n  \"profiles\": {\n    \"b\": {\n      \"host\": \"h2\",\n      \"port\": 3269\n    },\n    \"a\": {\n      \"host\": \"h\",\n      \"bookmarks\": [{\"name\": \"old\", \"dn\": \"ou=old,dc=x\"}]\n    }\n  }\n}\n";
        std::fs::write(&path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut cfg = Config::load(&path).unwrap();
        // Edit made outside the app after loading must survive.
        std::fs::write(&path, original.replace("3269", "3268")).unwrap();
        let a = cfg.profile_mut("a").unwrap();
        a.bookmarks = vec![Bookmark { name: "people".into(), dn: "ou=people,dc=x".into() }];
        a.search.saved = vec![SavedSearch { name: "s".into(), filter: "(uid={q})".into(), base: None, scope: None }];
        cfg.search.saved =
            vec![SavedSearch { name: "g".into(), filter: "(cn=*)".into(), base: None, scope: Some("base".into()) }];
        cfg.persist().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("3268"), "external edit lost:\n{text}");
        assert!(text.find("\"b\"").unwrap() < text.find("\"a\"").unwrap(), "key order changed:\n{text}");
        assert!(text.ends_with("}\n"));
        assert!(!text.contains("old"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let again = Config::load(&path).unwrap();
        assert_eq!(again.profile("a").unwrap().bookmarks[0].name, "people");
        assert_eq!(again.profile("a").unwrap().search.saved[0].filter, "(uid={q})");
        assert_eq!(again.search.saved[0].scope.as_deref(), Some("base"));
        assert_eq!(again.profile("b").unwrap().port(), 3268);
        // Clearing removes the keys again rather than leaving empty arrays.
        let mut again = again;
        again.profile_mut("a").unwrap().bookmarks.clear();
        again.profile_mut("a").unwrap().search.saved.clear();
        again.search.saved.clear();
        again.persist().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("bookmarks") && !text.contains("saved") && !text.contains("\"search\""), "{text}");
        assert!(std::fs::read_dir(&dir).unwrap().count() == 1, "temp file left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn results_columns_validate() {
        let cfg = Config::parse(
            r#"{"profiles":{"a":{"host":"h","results":{"columns":{"users":["mail","parent"]},"sort":"whenCreated:desc"}}}}"#,
            None,
        )
        .unwrap();
        assert_eq!(cfg.profile("a").unwrap().results.columns.get("users").unwrap(), &["mail", "parent"]);
        assert!(cfg.profile("a").unwrap().results.columns.get("groups").is_none());
        let err = Config::parse(r#"{"profiles":{"a":{"host":"h","results":{"columns":{"users":["(bad)"]}}}}}"#, None)
            .unwrap_err();
        assert!(err.to_string().contains("results.columns.users"), "{err}");
        assert!(Config::parse(r#"{"profiles":{"a":{"host":"h","results":{"sort":"a b"}}}}"#, None).is_err());
    }

    #[test]
    fn missing_ca_cert_is_rejected() {
        let err =
            Config::parse(r#"{"profiles":{"a":{"host":"h","ca_cert":"/nonexistent/ca.pem"}}}"#, None).unwrap_err();
        assert!(err.to_string().contains("ca_cert"));
    }
}
