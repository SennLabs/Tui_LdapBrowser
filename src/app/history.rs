//! Search history persisted to `$XDG_STATE_HOME/ldaptui/history.json`, per profile and
//! search type. Holds only the typed text (filters, names, DNs), never results or credentials.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::warn;

pub const MAX_PER_KIND: usize = 50;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SearchHistory {
    /// profile -> search kind label -> entries, oldest first.
    #[serde(flatten)]
    profiles: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl SearchHistory {
    /// Loads the history file if it exists. Errors are logged and yield an empty history, so a
    /// damaged file never stops the app from starting.
    pub fn load(path: PathBuf) -> SearchHistory {
        let mut h = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<SearchHistory>(&text).unwrap_or_else(|e| {
                warn!(path = %path.display(), "ignoring unreadable history file: {e}");
                SearchHistory::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => SearchHistory::default(),
            Err(e) => {
                warn!(path = %path.display(), "cannot read history file: {e}");
                SearchHistory::default()
            }
        };
        h.path = Some(path);
        h
    }

    /// Most recent first.
    pub fn entries(&self, profile: &str, kind: &str) -> Vec<String> {
        self.profiles
            .get(profile)
            .and_then(|k| k.get(kind))
            .map(|v| v.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    /// Most recent first, limited to entries starting with `prefix` (case-insensitive).
    pub fn matching(&self, profile: &str, kind: &str, prefix: &str) -> Vec<String> {
        let p = prefix.to_ascii_lowercase();
        self.entries(profile, kind).into_iter().filter(|e| e.to_ascii_lowercase().starts_with(&p)).collect()
    }

    pub fn remember(&mut self, profile: &str, kind: &str, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        let list = self.profiles.entry(profile.to_string()).or_default().entry(kind.to_string()).or_default();
        list.retain(|s| s != text);
        list.push(text.to_string());
        if list.len() > MAX_PER_KIND {
            let excess = list.len() - MAX_PER_KIND;
            list.drain(..excess);
        }
        self.save();
    }

    pub fn forget(&mut self, profile: &str, kind: &str, text: &str) {
        if let Some(list) = self.profiles.get_mut(profile).and_then(|k| k.get_mut(kind)) {
            list.retain(|s| s != text);
            self.save();
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let result = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let text = serde_json::to_string_pretty(&self.profiles)?;
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, text)?;
            std::fs::rename(&tmp, path)
        })();
        if let Err(e) = result {
            warn!(path = %path.display(), "cannot save search history: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_dedupes_caps_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("ldaptui-hist-test-{}", std::process::id()));
        let path = dir.join("history.json");
        let mut h = SearchHistory::load(path.clone());
        for i in 0..60 {
            h.remember("corp", "raw", &format!("(uid={i})"));
        }
        h.remember("corp", "raw", "(uid=5)");
        h.remember("corp", "users", "jane");
        h.remember("lab", "users", "bob");
        let raw = h.entries("corp", "raw");
        assert_eq!(raw.len(), MAX_PER_KIND);
        assert_eq!(raw[0], "(uid=5)", "re-remembered entry moves to the front");
        assert_eq!(raw[1], "(uid=59)");
        assert!(!raw.contains(&"(uid=9)".to_string()), "oldest entries dropped");
        assert_eq!(h.entries("corp", "users"), vec!["jane"]);
        assert_eq!(
            h.matching("corp", "raw", "(UID=5"),
            [
                "(uid=5)", "(uid=59)", "(uid=58)", "(uid=57)", "(uid=56)", "(uid=55)", "(uid=54)", "(uid=53)",
                "(uid=52)", "(uid=51)", "(uid=50)"
            ]
        );

        let again = SearchHistory::load(path.clone());
        assert_eq!(again.entries("corp", "raw"), raw);
        assert_eq!(again.entries("lab", "users"), vec!["bob"]);
        let mut again = again;
        again.forget("corp", "users", "jane");
        assert!(SearchHistory::load(path).entries("corp", "users").is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_file_is_ignored() {
        let dir = std::env::temp_dir().join(format!("ldaptui-hist-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.json");
        std::fs::write(&path, "{not json").unwrap();
        let h = SearchHistory::load(path);
        assert!(h.entries("x", "raw").is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
