//! Integration tests against a local OpenLDAP. Start it first:
//!
//!     scripts/test-slapd.sh start
//!     cargo test --test openldap -- --ignored
//!
//! Seed data: scripts/seed-ldif.sh. The server's unpaged size limit is 100 entries.

mod common;

use common::*;
use ldap3::Scope;
use ldaptui::ldap::error::ErrorKind;
use ldaptui::ldap::flavor::Flavor;
use ldaptui::ldap::model::{EntryKind, Value};
use ldaptui::ldap::session::{Creds, Session};

const PLAIN: &str = r#"{"host":"localhost","port":10389,"scheme":"ldap"}"#;
const LDAPS_CA: &str = r#"{"host":"localhost","port":10636,"scheme":"ldaps","ca_cert":"ca.pem"}"#;
const BASE: &str = "dc=example,dc=org";
const ADMIN: &str = "cn=admin,dc=example,dc=org";
const ALICE: &str = "uid=alice,ou=people,dc=example,dc=org";

async fn admin() -> Session {
    connect(PLAIN, simple(ADMIN, "admin")).await
}

#[tokio::test]
#[ignore]
async fn anonymous_plain_bind_and_detection() {
    let s = connect(PLAIN, Creds::Anonymous).await;
    assert_eq!(s.flavor, Flavor::OpenLdap);
    assert_eq!(s.base_dn, BASE);
    assert!(s.bound_as.is_none());
}

#[tokio::test]
#[ignore]
async fn authenticated_bind_over_ldaps_with_ca() {
    let s = connect(LDAPS_CA, simple(ALICE, "alicepw")).await;
    assert_eq!(s.bound_as.as_deref(), Some(ALICE));
}

#[tokio::test]
#[ignore]
async fn ldaps_insecure_skip_verify_succeeds() {
    connect(r#"{"host":"localhost","port":10636,"scheme":"ldaps","insecure_skip_verify":true}"#, Creds::Anonymous)
        .await;
}

#[tokio::test]
#[ignore]
async fn ldaps_untrusted_ca_fails_clearly() {
    let p = profile(r#"{"host":"localhost","port":10636,"scheme":"ldaps","ca_cert":"other-ca.pem"}"#);
    let f = Session::connect(p, Creds::Anonymous).await.err().expect("must fail");
    assert_eq!(f.kind, ErrorKind::CertUntrusted, "{f}");
}

#[tokio::test]
#[ignore]
async fn ldaps_by_ip_gives_name_mismatch() {
    let p = profile(r#"{"host":"127.0.0.1","port":10636,"scheme":"ldaps","ca_cert":"ca.pem"}"#);
    let f = Session::connect(p, Creds::Anonymous).await.err().expect("must fail");
    assert_eq!(f.kind, ErrorKind::CertNameMismatch, "{f}");
    assert!(f.title.contains("localhost"));
}

#[tokio::test]
#[ignore]
async fn bad_password_is_invalid_credentials() {
    let f = Session::connect(profile(PLAIN), simple(ALICE, "wrong")).await.err().expect("must fail");
    assert_eq!(f.kind, ErrorKind::InvalidCredentials);
    assert_eq!(f.rc, Some(49));
}

#[tokio::test]
#[ignore]
async fn lists_children_sorted_with_containers_first() {
    let s = admin().await;
    let c = s.list_children(BASE, None, 1000, &slot()).await.unwrap();
    let names: Vec<_> = c.children.iter().map(|c| c.dn.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "ou=bulk,dc=example,dc=org",
            "ou=empty,dc=example,dc=org",
            "ou=groups,dc=example,dc=org",
            "ou=people,dc=example,dc=org"
        ]
    );
    assert!(c.children.iter().all(|c| c.kind == EntryKind::OrgUnit));
    assert_eq!(c.children[1].has_children, Some(false));
    assert!(!c.truncated);
}

#[tokio::test]
#[ignore]
async fn paging_returns_more_than_server_size_limit() {
    // Anonymous users are limited to 100 unpaged results; paging must get all 250.
    let s = connect(PLAIN, Creds::Anonymous).await;
    let c = s.list_children("ou=bulk,dc=example,dc=org", None, 1000, &slot()).await.unwrap();
    assert_eq!(c.children.len(), 250);
    assert!(!c.truncated);
}

#[tokio::test]
#[ignore]
async fn child_limit_truncates_and_load_more_extends() {
    let s = connect(PLAIN, Creds::Anonymous).await;
    let c = s.list_children("ou=bulk,dc=example,dc=org", None, 40, &slot()).await.unwrap();
    assert_eq!(c.children.len(), 40);
    assert!(c.truncated);
    let c = s.list_children("ou=bulk,dc=example,dc=org", None, 80, &slot()).await.unwrap();
    assert_eq!(c.children.len(), 80);
}

#[tokio::test]
#[ignore]
async fn prefix_filter_on_children() {
    let s = admin().await;
    let c = s.list_children("ou=bulk,dc=example,dc=org", Some("user02"), 1000, &slot()).await.unwrap();
    assert_eq!(c.children.len(), 10); // user020..user029
}

#[tokio::test]
#[ignore]
async fn read_entry_includes_operational_and_memberof() {
    let s = admin().await;
    let e = s.read_entry(ALICE, &slot()).await.unwrap();
    assert_eq!(e.attrs[0].name, "objectClass");
    assert_eq!(e.kind(), EntryKind::User);
    assert!(e.get("createTimestamp").is_some_and(|a| a.operational));
    let groups = e.texts("memberOf");
    assert_eq!(groups.len(), 2, "{groups:?}");
    assert!(e.get("memberOf").is_some_and(|a| !a.operational));
}

#[tokio::test]
#[ignore]
async fn entry_with_escaped_comma_in_rdn() {
    let s = admin().await;
    let e = s.read_entry(r"cn=Doe\, Jane,ou=people,dc=example,dc=org", &slot()).await.unwrap();
    assert_eq!(e.first_text("sn"), Some("Doe"));
    assert!(matches!(&e.get("manager").unwrap().values[0], Value::Text(m) if m == ALICE));
}

#[tokio::test]
#[ignore]
async fn missing_entry_is_no_such_object() {
    let s = admin().await;
    let f = s.read_entry("uid=nobody,ou=people,dc=example,dc=org", &slot()).await.err().unwrap();
    assert_eq!(f.kind, ErrorKind::NoSuchObject);
}

#[tokio::test]
#[ignore]
async fn user_and_group_searches() {
    let s = admin().await;
    let p = profile(PLAIN);
    let f = ldaptui::ldap::flavor::user_filter(&p, s.flavor, "ali");
    let hl = s.search(BASE, Scope::Subtree, &f, &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 1);
    assert_eq!(hl.hits[0].name, "Alice Example");
    assert_eq!(hl.hits[0].detail, "alice@example.org");

    let f = ldaptui::ldap::flavor::group_filter(&p, s.flavor, "cycle");
    let hl = s.search(BASE, Scope::Subtree, &f, &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 2);
    assert!(hl.hits.iter().all(|h| h.kind == EntryKind::Group));
}

#[tokio::test]
#[ignore]
async fn attribute_and_raw_searches() {
    let s = admin().await;
    let f = ldaptui::ldap::filter::attribute_filter("mail=*@example.org").unwrap();
    assert_eq!(s.search(BASE, Scope::Subtree, &f, &slot()).await.unwrap().hits.len(), 4);
    let f = ldaptui::ldap::filter::raw_filter("(&(objectClass=posixGroup)(memberUid=bob))").unwrap();
    assert_eq!(s.search(BASE, Scope::Subtree, &f, &slot()).await.unwrap().hits.len(), 1);
}

#[tokio::test]
#[ignore]
async fn search_truncates_at_size_limit() {
    let s = connect(r#"{"host":"localhost","port":10389,"scheme":"ldap","size_limit":30}"#, Creds::Anonymous).await;
    let hl = s.search("ou=bulk,dc=example,dc=org", Scope::OneLevel, "(objectClass=*)", &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 30);
    assert!(hl.truncated);
}

#[tokio::test]
#[ignore]
async fn find_dn_exact_and_fallback() {
    let s = admin().await;
    let hl = s.find_dn(ALICE, &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 1);
    assert!(hl.warning.is_none());
    // Wrong OU: falls back to a search on the RDN value.
    let hl = s.find_dn("uid=alice,ou=wrong,dc=example,dc=org", &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 1);
    assert_eq!(hl.hits[0].dn, ALICE);
    assert!(hl.warning.is_some());
}

#[tokio::test]
#[ignore]
async fn members_of_group_including_memberuid() {
    let s = admin().await;
    let hl = s.members("cn=staff,ou=groups,dc=example,dc=org", &slot()).await.unwrap();
    let names: Vec<_> = hl.hits.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, vec!["Alice Example", "Bob Example"]);

    let hl = s.members("cn=posix-devs,ou=groups,dc=example,dc=org", &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 3);
    assert!(hl.hits.iter().any(|h| h.name == "ghost" && h.dn.is_empty()));
}

#[tokio::test]
#[ignore]
async fn member_of_direct_and_nested_with_cycle() {
    let s = admin().await;
    let bob = "uid=bob,ou=people,dc=example,dc=org";
    let direct = s.member_of(bob, false, &slot()).await.unwrap();
    let names: Vec<_> = direct.hits.iter().map(|h| h.name.as_str()).collect();
    // memberOf overlay covers groupOfNames; posixGroup membership needs the reverse search.
    assert_eq!(names, vec!["posix-devs", "staff"]);

    let nested = s.member_of(bob, true, &slot()).await.unwrap();
    let mut names: Vec<_> = nested.hits.iter().map(|h| (h.name.as_str(), h.tag.as_deref())).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            ("cycle-a", Some("nested")),
            ("cycle-b", Some("nested")),
            ("everyone", Some("nested")),
            ("posix-devs", None),
            ("staff", None)
        ]
    );
}

#[tokio::test]
#[ignore]
async fn member_of_includes_memberuid_groups() {
    // carol is in posix-devs only via memberUid (not covered by the memberOf overlay),
    // and in everyone via member.
    let s = admin().await;
    let hl = s.member_of("uid=carol,ou=people,dc=example,dc=org", false, &slot()).await.unwrap();
    let mut names: Vec<_> = hl.hits.iter().map(|h| h.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["everyone", "posix-devs"]);
}

#[tokio::test]
#[ignore]
async fn member_of_without_memberof_attribute() {
    // A non-person entry has no memberOf; groups are still found by reverse search.
    let s = admin().await;
    let hl = s.member_of("cn=staff,ou=groups,dc=example,dc=org", false, &slot()).await.unwrap();
    let names: Vec<_> = hl.hits.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, vec!["everyone"]);
}

#[tokio::test]
#[ignore]
async fn worker_round_trip() {
    use ldaptui::ldap::worker::{Request, Response, Worker};
    let mut w = Worker::spawn();
    let id = w.send(Request::Connect { profile: Box::new(profile(PLAIN)), creds: Creds::Anonymous });
    let reply = wait(&w);
    assert_eq!(reply.id, id);
    assert!(matches!(reply.response, Response::Connected(_)));
    let id = w.send(Request::Entry { dn: ALICE.into() });
    let reply = wait(&w);
    assert_eq!(reply.id, id);
    assert!(matches!(reply.response, Response::Entry(e) if e.dn == ALICE));
}

fn wait(w: &ldaptui::ldap::worker::Worker) -> ldaptui::ldap::worker::Reply {
    let start = std::time::Instant::now();
    loop {
        if let Some(r) = w.try_recv() {
            return r;
        }
        assert!(start.elapsed().as_secs() < 10, "timed out waiting for worker");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[tokio::test]
#[ignore]
async fn search_with_extra_attributes_fills_hit_values() {
    let s = admin().await;
    let extra = vec!["uidNumber".to_string(), "mail".to_string(), "nothere".to_string()];
    let hl = s.search_with(BASE, Scope::Subtree, "(uid=alice)", &extra, &slot()).await.unwrap();
    assert_eq!(hl.hits.len(), 1);
    let h = &hl.hits[0];
    assert_eq!(h.values("uidNumber"), [Value::Text("1005".into())]);
    assert_eq!(h.values("MAIL"), [Value::Text("alice@example.org".into())]);
    assert!(h.values("nothere").is_empty());
    assert!(h.partial.is_empty());
    // Member rows carry extra attributes too.
    let m = s.members_with("cn=staff,ou=groups,dc=example,dc=org", &extra, &slot()).await.unwrap();
    assert!(m.hits.iter().all(|h| !h.values("uidNumber").is_empty()), "{:?}", m.hits);
    // Without extras, only the summary attributes are present.
    let plain = s.search(BASE, Scope::Subtree, "(uid=alice)", &slot()).await.unwrap();
    assert!(plain.hits[0].values("uidNumber").is_empty());
    assert!(!plain.hits[0].values("mail").is_empty());
}
