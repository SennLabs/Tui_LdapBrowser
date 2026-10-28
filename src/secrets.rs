//! Credentials loaded from `secrets.json`, and resolution of what a profile needs to bind.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use secrecy::SecretString;
use serde::Deserialize;

use crate::config::Profile;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential {
    #[serde(alias = "username")]
    bind_dn: Option<String>,
    password: Option<String>,
    password_env: Option<String>,
}

pub struct Credential {
    pub bind_dn: Option<String>,
    pub password: Option<SecretString>,
    pub password_env: Option<String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("bind_dn", &self.bind_dn)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("password_env", &self.password_env)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct Secrets {
    creds: HashMap<String, Credential>,
}

/// What is needed to bind for a profile, after consulting `secrets.json` and the environment.
#[derive(Debug, Clone)]
pub enum Resolution {
    Anonymous,
    Ready { bind_dn: String, password: SecretString },
    NeedPassword { bind_dn: String },
    NeedBoth,
}

impl Secrets {
    /// Loads secrets. A missing file is not an error (every credential will be prompted for).
    /// Returns warnings to show the user, e.g. about loose file permissions.
    pub fn load(path: &Path) -> Result<(Secrets, Vec<String>)> {
        let mut warnings = Vec::new();
        if !path.exists() {
            warnings.push(format!("secrets file {} not found; credentials will be prompted for", path.display()));
            return Ok((Secrets::default(), warnings));
        }
        if let Some(w) = permission_warning(path) {
            warnings.push(w);
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("cannot read secrets file {}", path.display()))?;
        let secrets = Self::parse(&text).with_context(|| format!("invalid secrets file {}", path.display()))?;
        Ok((secrets, warnings))
    }

    pub fn parse(text: &str) -> Result<Secrets> {
        let raw: HashMap<String, RawCredential> = serde_json::from_str(text)?;
        let creds = raw
            .into_iter()
            .map(|(k, r)| {
                (
                    k,
                    Credential {
                        bind_dn: r.bind_dn.filter(|s| !s.is_empty()),
                        password: r.password.filter(|s| !s.is_empty()).map(SecretString::from),
                        password_env: r.password_env,
                    },
                )
            })
            .collect();
        Ok(Secrets { creds })
    }

    pub fn resolve(&self, profile: &Profile) -> Resolution {
        self.resolve_with_env(profile, |k| std::env::var(k).ok())
    }

    fn resolve_with_env(&self, profile: &Profile, env: impl Fn(&str) -> Option<String>) -> Resolution {
        let Some(key) = &profile.credentials else {
            return Resolution::Anonymous;
        };
        let Some(cred) = self.creds.get(key) else {
            return Resolution::NeedBoth;
        };
        let Some(bind_dn) = cred.bind_dn.clone() else {
            return Resolution::NeedBoth;
        };
        if let Some(pw) = &cred.password {
            return Resolution::Ready { bind_dn, password: pw.clone() };
        }
        if let Some(var) = &cred.password_env
            && let Some(pw) = env(var).filter(|s| !s.is_empty())
        {
            return Resolution::Ready { bind_dn, password: SecretString::from(pw) };
        }
        Resolution::NeedPassword { bind_dn }
    }
}

#[cfg(unix)]
fn permission_warning(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then(|| {
        format!(
            "secrets file {} is readable by other users (mode {:o}); run: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn permission_warning(_: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use secrecy::ExposeSecret;

    fn profile(creds: Option<&str>) -> Profile {
        let c = match creds {
            Some(c) => format!(r#""credentials":"{c}""#),
            None => r#""credentials":null"#.into(),
        };
        let cfg = Config::parse(&format!(r#"{{"profiles":{{"p":{{"host":"h",{c}}}}}}}"#), None).unwrap();
        cfg.profile("p").unwrap().clone()
    }

    const SECRETS: &str = r#"{
        "full": {"bind_dn": "cn=a", "password": "pw"},
        "upn": {"username": "a@example.local", "password": "pw"},
        "nopw": {"bind_dn": "cn=b"},
        "env": {"bind_dn": "cn=c", "password_env": "LDAPTUI_TEST_PW"},
        "empty": {}
    }"#;

    fn resolve(name: Option<&str>) -> Resolution {
        let s = Secrets::parse(SECRETS).unwrap();
        s.resolve_with_env(&profile(name), |k| (k == "LDAPTUI_TEST_PW").then(|| "from-env".to_string()))
    }

    #[test]
    fn anonymous_when_no_credentials() {
        assert!(matches!(resolve(None), Resolution::Anonymous));
    }

    #[test]
    fn ready_with_password() {
        match resolve(Some("full")) {
            Resolution::Ready { bind_dn, password } => {
                assert_eq!(bind_dn, "cn=a");
                assert_eq!(password.expose_secret(), "pw");
            }
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn username_alias() {
        assert!(matches!(resolve(Some("upn")), Resolution::Ready { bind_dn, .. } if bind_dn == "a@example.local"));
    }

    #[test]
    fn password_from_env() {
        match resolve(Some("env")) {
            Resolution::Ready { password, .. } => assert_eq!(password.expose_secret(), "from-env"),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn missing_password_prompts() {
        assert!(matches!(resolve(Some("nopw")), Resolution::NeedPassword { bind_dn } if bind_dn == "cn=b"));
    }

    #[test]
    fn missing_key_or_dn_prompts_for_both() {
        assert!(matches!(resolve(Some("nope")), Resolution::NeedBoth));
        assert!(matches!(resolve(Some("empty")), Resolution::NeedBoth));
    }

    #[test]
    fn debug_redacts_password() {
        let s = Secrets::parse(SECRETS).unwrap();
        let dbg = format!("{:?}", s.creds.get("full").unwrap());
        assert!(!dbg.contains("\"pw\""), "{dbg}");
        assert!(dbg.contains("REDACTED"));
    }

    #[cfg(unix)]
    #[test]
    fn warns_on_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ldaptui-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (_, w) = Secrets::load(&path).unwrap();
        assert!(w.iter().any(|w| w.contains("chmod 600")));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (_, w) = Secrets::load(&path).unwrap();
        assert!(w.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
