//! Optional tests against a real Active Directory domain controller. They are skipped unless
//! these environment variables are set:
//!
//!     LDAPTUI_AD_HOST        DC hostname (FQDN matching its certificate)
//!     LDAPTUI_AD_BIND_DN     bind DN, UPN (user@domain) or DOMAIN\user
//!     LDAPTUI_AD_PASSWORD    password
//!     LDAPTUI_AD_CA_CERT     optional PEM CA bundle; otherwise system roots are used
//!     LDAPTUI_AD_INSECURE    optional, "1" to skip certificate verification
//!     LDAPTUI_AD_GROUP_DN    optional, a group with members (for members/memberOf tests)
//!
//!     cargo test --test ad -- --ignored --test-threads=1

mod common;

use common::*;
use ldap3::Scope;
use ldaptui::ldap::flavor::{self, Flavor};
use ldaptui::ldap::session::Session;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

async fn ad() -> Option<Session> {
    let (Some(host), Some(dn), Some(pw)) =
        (env("LDAPTUI_AD_HOST"), env("LDAPTUI_AD_BIND_DN"), env("LDAPTUI_AD_PASSWORD"))
    else {
        eprintln!("skipping: LDAPTUI_AD_HOST / LDAPTUI_AD_BIND_DN / LDAPTUI_AD_PASSWORD not set");
        return None;
    };
    let mut json = format!(r#"{{"host":{},"scheme":"ldaps""#, serde_json::to_string(&host).unwrap());
    if let Some(ca) = env("LDAPTUI_AD_CA_CERT") {
        json.push_str(&format!(r#","ca_cert":{}"#, serde_json::to_string(&ca).unwrap()));
    }
    if env("LDAPTUI_AD_INSECURE").as_deref() == Some("1") {
        json.push_str(r#","insecure_skip_verify":true"#);
    }
    json.push('}');
    Some(connect(&json, simple(&dn, &pw)).await)
}

#[tokio::test]
#[ignore]
async fn detects_ad_and_pages() {
    let Some(s) = ad().await else { return };
    assert_eq!(s.flavor, Flavor::Ad);
    assert!(s.info().paging);
    let c = s.list_children(&s.base_dn, None, 1000, &slot()).await.unwrap();
    assert!(c.children.iter().any(|c| c.dn.to_ascii_lowercase().starts_with("cn=users,")));
}

#[tokio::test]
#[ignore]
async fn user_search_and_primary_group() {
    let Some(s) = ad().await else { return };
    let p = profile(r#"{"host":"x"}"#);
    let me = env("LDAPTUI_AD_BIND_DN").unwrap();
    let q = me.split(['@', '\\', ',']).find(|x| !x.is_empty()).unwrap().trim_start_matches("CN=").to_string();
    let hl = s.search(&s.base_dn, Scope::Subtree, &flavor::user_filter(&p, Flavor::Ad, &q), &slot()).await.unwrap();
    assert!(!hl.hits.is_empty(), "no user matching {q}");
    let groups = s.member_of(&hl.hits[0].dn, false, &slot()).await.unwrap();
    assert!(groups.hits.iter().any(|h| h.tag.as_deref() == Some("primary")), "primary group missing");
}

#[tokio::test]
#[ignore]
async fn members_with_ranged_retrieval_and_nested() {
    let Some(s) = ad().await else { return };
    let Some(g) = env("LDAPTUI_AD_GROUP_DN") else { return };
    let e = s.read_entry(&g, &slot()).await.unwrap();
    assert!(e.attrs.iter().all(|a| !a.name.contains(";range=")), "ranged attribute not merged");
    let m = s.members(&g, &slot()).await.unwrap();
    assert!(!m.hits.is_empty());
    if let Some(user) = m.hits.iter().find(|h| h.kind == ldaptui::ldap::model::EntryKind::User) {
        let nested = s.member_of(&user.dn, true, &slot()).await.unwrap();
        assert!(nested.hits.iter().any(|h| ldaptui::ldap::model::dn_eq(&h.dn, &g)));
    }
}
