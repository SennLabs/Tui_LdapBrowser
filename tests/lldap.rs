//! Integration tests against a local LLDAP. Start it first:
//!
//!     scripts/test-lldap.sh start
//!     cargo test --test lldap -- --ignored
//!
//! Seed data: users alice, bob, carol; groups staff (alice, bob) and admins (alice).

mod common;

use common::*;
use ldap3::Scope;
use ldaptui::ldap::error::ErrorKind;
use ldaptui::ldap::flavor::{self, Flavor};
use ldaptui::ldap::model::EntryKind;
use ldaptui::ldap::session::Session;

const PLAIN: &str = r#"{"host":"localhost","port":13890,"scheme":"ldap"}"#;
const LDAPS_CA: &str = r#"{"host":"localhost","port":16360,"scheme":"ldaps","ca_cert":"ca.pem"}"#;
const BASE: &str = "dc=example,dc=com";
const ADMIN: &str = "uid=admin,ou=people,dc=example,dc=com";
const ALICE: &str = "uid=alice,ou=people,dc=example,dc=com";

async fn admin() -> Session {
    connect(PLAIN, simple(ADMIN, "adminpass")).await
}

#[tokio::test]
#[ignore]
async fn detected_as_lldap_not_ad() {
    // LLDAP's RootDSE carries isGlobalCatalogReady: false, which must not mean AD.
    let s = admin().await;
    assert_eq!(s.flavor, Flavor::Lldap);
    assert_eq!(s.base_dn, BASE);
}

#[tokio::test]
#[ignore]
async fn ldaps_with_ca_and_user_bind() {
    let s = connect(LDAPS_CA, simple(ALICE, "alicepass1234")).await;
    assert_eq!(s.flavor, Flavor::Lldap);
}

#[tokio::test]
#[ignore]
async fn bad_password() {
    let f = Session::connect(profile(PLAIN), simple(ALICE, "nope")).await.err().unwrap();
    assert_eq!(f.kind, ErrorKind::InvalidCredentials);
}

#[tokio::test]
#[ignore]
async fn root_shows_people_and_groups_containers() {
    let s = admin().await;
    let c = s.list_children(BASE, None, 1000, &slot()).await.unwrap();
    let dns: Vec<_> = c.children.iter().map(|c| c.dn.as_str()).collect();
    assert_eq!(dns, vec!["ou=groups,dc=example,dc=com", "ou=people,dc=example,dc=com"]);
    // The root entry is synthesized rather than whatever LLDAP returns for a base search.
    let e = s.read_entry(BASE, &slot()).await.unwrap();
    assert_eq!(e.dn, BASE);
}

#[tokio::test]
#[ignore]
async fn lists_people_and_groups() {
    let s = admin().await;
    let people = s.list_children("ou=people,dc=example,dc=com", None, 1000, &slot()).await.unwrap();
    assert_eq!(people.children.len(), 4); // admin + 3 seeded
    assert!(people.children.iter().all(|c| c.kind == EntryKind::User));
    let groups = s.list_children("ou=groups,dc=example,dc=com", None, 1000, &slot()).await.unwrap();
    assert!(groups.children.iter().all(|c| c.kind == EntryKind::Group));
    assert!(groups.children.iter().any(|c| c.dn.starts_with("cn=staff")));
}

#[tokio::test]
#[ignore]
async fn child_limit_without_paging() {
    let s = admin().await;
    let c = s.list_children("ou=people,dc=example,dc=com", None, 2, &slot()).await.unwrap();
    assert_eq!(c.children.len(), 2);
    assert!(c.truncated);
}

#[tokio::test]
#[ignore]
async fn entry_includes_memberof() {
    let s = admin().await;
    let e = s.read_entry(ALICE, &slot()).await.unwrap();
    assert_eq!(e.kind(), EntryKind::User);
    assert_eq!(e.texts("memberOf").len(), 2);
    assert!(e.attrs[0].name.eq_ignore_ascii_case("objectClass"));
}

#[tokio::test]
#[ignore]
async fn user_and_group_search() {
    let s = admin().await;
    let p = profile(PLAIN);
    let hl = s.search(BASE, Scope::Subtree, &flavor::user_filter(&p, s.flavor, "li"), &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 1);
    assert_eq!(hl.hits[0].name, "Alice Example");
    let hl = s.search(BASE, Scope::Subtree, &flavor::group_filter(&p, s.flavor, "staff"), &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 1);
}

#[tokio::test]
#[ignore]
async fn members_and_member_of() {
    let s = admin().await;
    let m = s.members("cn=staff,ou=groups,dc=example,dc=com", &slot()).await.unwrap();
    let names: Vec<_> = m.hits.iter().map(|h| h.name.as_str()).collect();
    // member and uniqueMember both list the same users; they must not appear twice.
    assert_eq!(names, vec!["Alice Example", "Bob Example"]);

    let g = s.member_of(ALICE, true, &slot()).await.unwrap();
    let mut names: Vec<_> = g.hits.iter().map(|h| h.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["admins", "staff"]);
    assert!(g.hits.iter().all(|h| h.tag.is_none()), "LLDAP has no nesting");
}
