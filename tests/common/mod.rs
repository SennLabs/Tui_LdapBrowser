//! Shared helpers for integration tests. Servers are started by scripts/test-*.sh.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;

use ldaptui::config::{Config, Profile};
use ldaptui::ldap::session::{Creds, MsgSlot, Session};
use secrecy::SecretString;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn certs() -> PathBuf {
    root().join("target/test-ldap/certs")
}

/// Builds a profile from a JSON fragment; relative `ca_cert` paths resolve against the certs dir.
pub fn profile(json: &str) -> Profile {
    let cfg = Config::parse(&format!(r#"{{"profiles":{{"t":{json}}}}}"#), Some(&certs())).expect("valid test profile");
    cfg.profile("t").unwrap().clone()
}

pub fn simple(dn: &str, pw: &str) -> Creds {
    Creds::Simple { bind_dn: dn.into(), password: SecretString::from(pw.to_string()) }
}

pub fn slot() -> MsgSlot {
    Arc::new(AtomicI32::new(0))
}

pub async fn connect(json: &str, creds: Creds) -> Session {
    Session::connect(profile(json), creds).await.unwrap_or_else(|f| panic!("connect failed: {f} / {}", f.detail))
}
