//! Render tests against ratatui's TestBackend.

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use crate::app::App;
use crate::config::Config;
use crate::secrets::Secrets;

const CONFIG: &str = r#"{
  "profiles": {
    "corp-ad": {"host": "dc01.example.local", "flavor": "ad", "credentials": "svc"},
    "lab": {"host": "10.0.0.5", "insecure_skip_verify": true},
    "dev": {"host": "localhost", "scheme": "ldap", "port": 3890}
  }
}"#;

fn app() -> App {
    let cfg = Config::parse(CONFIG, None).unwrap();
    App::new(cfg, Secrets::default(), true, vec![])
}

fn render(app: &mut App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| super::draw(f, app)).unwrap();
    let buf = t.backend().buffer().clone();
    (0..h).map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>()).collect::<Vec<_>>().join("\n")
}

#[test]
fn picker_lists_profiles_with_tls_badges() {
    let mut a = app();
    let s = render(&mut a, 120, 30);
    assert!(s.contains("Choose a profile"));
    assert!(s.contains("ldaps://dc01.example.local:636"));
    assert!(s.contains("ldap://localhost:3890"));
    let lab = s.lines().find(|l| l.contains("10.0.0.5")).unwrap();
    assert!(lab.contains("INSECURE TLS"), "{lab}");
    let dev = s.lines().find(|l| l.contains("localhost:3890")).unwrap();
    assert!(dev.contains("PLAIN") && dev.contains("anonymous"), "{dev}");
}

#[test]
fn login_prompt_when_credentials_missing() {
    let mut a = app();
    a.start_profile("corp-ad"); // "svc" is not in secrets: ask for DN and password
    let s = render(&mut a, 120, 30);
    assert!(s.contains("Log in to corp-ad"));
    assert!(s.contains("Bind DN or username"));
    assert!(s.contains("Ctrl-N anonymous"));
    assert!(!s.contains("unencrypted"), "LDAPS profile must not warn about plain LDAP");
}

#[test]
fn login_masks_password() {
    use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut a = app();
    a.start_profile("corp-ad");
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
    a.handle_event(Event::Paste("hunter2".into()));
    let s = render(&mut a, 120, 30);
    assert!(!s.contains("hunter2"));
    assert!(s.contains("•••••••"));
}

#[test]
fn too_small_terminal() {
    let mut a = app();
    let s = render(&mut a, 60, 20);
    assert!(s.contains("Terminal too small"));
}

#[test]
fn help_overlay() {
    use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut a = app();
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)));
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Help"));
    assert!(s.contains("go to a DN"));
}

// ---------------------------------------------------------------------------------------------
// Entry filter and diff (section 5.6.2 / 5.6.5)

use crate::app::Screen;
use crate::ldap::model::{self, Attribute, Entry, Value};
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

fn key(a: &mut App, c: char) {
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)));
}

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

/// A connected-looking app showing `e` in the entry pane, without a server.
fn browsing(e: Entry) -> App {
    let mut a = app();
    a.profile = a.config.profile("corp-ad").cloned();
    a.screen = Screen::Browse;
    a.focus = crate::app::Focus::Right;
    a.entry.dn = Some(e.dn.clone());
    a.entry.entry = Some(e);
    a.entry.state.select(Some(0));
    a
}

fn jane() -> Entry {
    entry(
        "CN=Jane,OU=Staff,DC=example,DC=local",
        &[
            ("objectClass", &["top", "user"]),
            ("cn", &["Jane"]),
            ("mail", &["jane@example.local"]),
            ("department", &["Radiology"]),
            ("lastLogonTimestamp", &["0"]),
            ("uSNChanged", &["100"]),
        ],
    )
}

#[test]
fn attribute_filter_is_live_and_shows_counts() {
    let mut a = browsing(jane());
    key(&mut a, ':');
    a.handle_event(Event::Paste("logon".into()));
    let s = render(&mut a, 120, 30);
    assert!(s.contains("filter: logon (1 of 5)"), "{s}");
    assert!(s.contains("lastLogonTimestamp"));
    assert!(!s.contains("department"), "filtered-out attribute still rendered:\n{s}");
    assert!(s.contains("Enter keep"));
    // Enter keeps the filter and closes the input line; the filter survives a new entry.
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
    assert!(a.overlay.is_none());
    assert_eq!(a.entry.filter.as_deref(), Some("logon"));
    a.entry.entry = Some(entry("CN=John,DC=example,DC=local", &[("lastLogon", &["0"]), ("mail", &["j@x"])]));
    assert_eq!(a.entry.rows().len(), 1);
    // Esc in the entry pane clears it before moving focus.
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(a.entry.filter.is_none());
    assert_eq!(a.focus, crate::app::Focus::Right);
    let s = render(&mut a, 120, 30);
    assert!(!s.contains("filter:"), "{s}");
}

#[test]
fn attribute_filter_esc_clears() {
    let mut a = browsing(jane());
    key(&mut a, ':');
    a.handle_event(Event::Paste("zzz".into()));
    let s = render(&mut a, 120, 30);
    assert!(s.contains("No attribute matches the filter."), "{s}");
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(a.overlay.is_none() && a.entry.filter.is_none());
}

#[test]
fn mark_and_diff_entries() {
    let mut a = browsing(jane());
    key(&mut a, 'D');
    assert!(a.overlay.is_none(), "D without a mark must not open the diff");
    key(&mut a, 'd');
    let s = render(&mut a, 120, 30);
    assert!(s.contains("compare: Jane"), "{s}");
    // Same entry: refuses.
    key(&mut a, 'D');
    assert!(a.overlay.is_none());
    a.entry.entry = Some(entry(
        "CN=John,OU=Staff,DC=example,DC=local",
        &[
            ("objectClass", &["top", "user"]),
            ("cn", &["John"]),
            ("mail", &["john@example.local"]),
            ("title", &["Boss"]),
            ("lastLogonTimestamp", &["0"]),
            ("uSNChanged", &["200"]),
        ],
    ));
    a.entry.dn = Some("CN=John,OU=Staff,DC=example,DC=local".into());
    key(&mut a, 'D');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Diff"), "{s}");
    assert!(s.contains("(marked)") && s.contains("(current)"));
    assert!(s.contains("jane@example.local") && s.contains("john@example.local"));
    assert!(s.contains("department") && s.contains("Boss"));
    assert!(!s.contains("objectClass"), "equal attributes hidden by default:\n{s}");
    assert!(s.contains("identity attribute"), "{s}");
    assert!(!s.contains("uSNChanged"), "operational hidden by default:\n{s}");
    key(&mut a, 'a');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("objectClass"), "{s}");
    key(&mut a, 'o');
    key(&mut a, 'i');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("uSNChanged") && s.contains("200"), "{s}");
    // Inline filter inside the diff.
    key(&mut a, ':');
    a.handle_event(Event::Paste("mail".into()));
    let s = render(&mut a, 120, 40);
    assert!(s.contains("filter: mail"), "{s}");
    assert!(!s.contains("Boss"), "{s}");
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(a.overlay.is_none());
    assert!(a.compare.is_some(), "closing the diff keeps the mark");
    key(&mut a, 'd');
    assert!(a.compare.is_some(), "d on a different entry re-marks rather than clears");
    assert_eq!(model::rdn_value(&a.compare.as_ref().unwrap().dn), "John");
    key(&mut a, 'd');
    assert!(a.compare.is_none());
}

// ---------------------------------------------------------------------------------------------
// Saved searches, history recall and bookmarks (section 5.6.3 / 5.6.4)

fn ctrl(a: &mut App, c: char) {
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)));
}

fn press(a: &mut App, code: KeyCode) {
    a.handle_event(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
}

/// A browsing app whose config lives in a temp file, so saving can be verified on disk.
fn browsing_with_file(tag: &str) -> (App, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ldaptui-ui-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, CONFIG).unwrap();
    let cfg = Config::load(&path).unwrap();
    let mut a = App::new(cfg, Secrets::default(), true, vec![]);
    a.profile = a.config.profile("corp-ad").cloned();
    a.screen = Screen::Browse;
    a.entry.dn = Some(jane().dn.clone());
    a.entry.entry = Some(jane());
    (a, path)
}

#[test]
fn save_search_writes_config_and_saved_tab_lists_it() {
    let (mut a, path) = browsing_with_file("save");
    key(&mut a, '/');
    // Switch to Raw filter: Users → Groups → DN → Attribute → Raw.
    for _ in 0..4 {
        a.handle_event(Event::Key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL)));
    }
    a.handle_event(Event::Paste("(&(objectClass=user)(department={q}))".into()));
    ctrl(&mut a, 's');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Save search as"), "{s}");
    assert!(s.contains("this profile") && s.contains("all profiles"));
    // Name defaults to the query; replace it.
    ctrl(&mut a, 'u');
    a.handle_event(Event::Paste("by department".into()));
    press(&mut a, KeyCode::Enter);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"by department\""), "{text}");
    assert!(text.contains("department={q}"), "{text}");
    assert!(text.contains("\"corp-ad\""), "other profiles kept:\n{text}");
    // The Saved tab lists it, Enter asks for the {q} text, and the prompt names the search.
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL)));
    let s = render(&mut a, 120, 40);
    assert!(s.contains("by department"), "{s}");
    assert!(s.contains("(&(objectClass=user)(department={q}))"), "{s}");
    press(&mut a, KeyCode::Enter);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("text for {q} in \"by department\""), "{s}");
    // Delete it from the Saved tab and the file is updated again.
    press(&mut a, KeyCode::Esc);
    key(&mut a, '/');
    a.handle_event(Event::Key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL))); // Users → Saved (wraps)
    let s = render(&mut a, 120, 40);
    assert!(s.contains("by department"), "{s}");
    key(&mut a, 'd');
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("by department"), "{text}");
    let s = render(&mut a, 120, 40);
    assert!(s.contains("No saved searches"), "{s}");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn history_recall_is_prefix_filtered_and_forgettable() {
    let mut a = browsing(jane());
    a.search_history.remember("corp-ad", "raw", "(cn=alpha)");
    a.search_history.remember("corp-ad", "raw", "(uid=bravo)");
    a.search_history.remember("corp-ad", "raw", "(cn=charlie)");
    key(&mut a, '/');
    for _ in 0..4 {
        a.handle_event(Event::Key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL)));
    }
    a.handle_event(Event::Paste("(cn".into()));
    press(&mut a, KeyCode::Up);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("(cn=charlie)"), "{s}");
    press(&mut a, KeyCode::Up);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("(cn=alpha)"), "uid entry must be skipped:\n{s}");
    ctrl(&mut a, 'd');
    assert!(!a.search_history.entries("corp-ad", "raw").contains(&"(cn=alpha)".to_string()));
    let s = render(&mut a, 120, 40);
    assert!(s.contains("(cn=charlie)"), "{s}");
    press(&mut a, KeyCode::Down);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("(cn ") || s.lines().any(|l| l.trim_end().ends_with("(cn")), "typed text restored:\n{s}");
}

#[test]
fn bookmarks_add_list_and_marker() {
    let (mut a, path) = browsing_with_file("bm");
    a.focus = crate::app::Focus::Right;
    key(&mut a, 'B');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Bookmark") && s.contains("CN=Jane,OU=Staff"), "{s}");
    ctrl(&mut a, 'u');
    a.handle_event(Event::Paste("Jane's account".into()));
    press(&mut a, KeyCode::Enter);
    assert!(a.is_bookmarked("cn=jane,ou=staff,dc=example,dc=local"), "case-insensitive DN match");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("Jane's account"), "{text}");
    // The list shows it and renames it.
    key(&mut a, '\'');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Jane's account"), "{s}");
    assert!(s.contains("* Jane's account"), "ascii marker in list:\n{s}");
    key(&mut a, 'e');
    ctrl(&mut a, 'u');
    a.handle_event(Event::Paste("Jane".into()));
    press(&mut a, KeyCode::Enter);
    assert_eq!(a.bookmarks()[0].name, "Jane");
    // Results rows carry the marker.
    press(&mut a, KeyCode::Esc);
    a.results = Some(crate::app::ResultsView {
        title: "test".into(),
        kind: crate::app::ResultsKind::Search { description: String::new() },
        list: crate::ldap::model::HitList {
            hits: vec![crate::ldap::model::Hit::bare(
                &jane().dn,
                crate::ldap::model::EntryKind::User,
                "Jane".into(),
                String::new(),
            )],
            ..Default::default()
        },
        state: Default::default(),
        loading: None,
        started: std::time::Instant::now(),
        kind_key: "users",
        columns: vec![],
        sort: (None, false),
        order: vec![0],
        request: None,
        requested: vec![],
        tree: None,
    });
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Jane *"), "{s}");
    // B again removes it.
    key(&mut a, 'B');
    assert!(a.bookmarks().is_empty());
    assert!(!std::fs::read_to_string(&path).unwrap().contains("bookmarks"));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Result sorting and columns (section 5.6.7)

fn results_with_values() -> App {
    use crate::ldap::model::{EntryKind, Hit, HitList};
    let mut a = browsing(jane());
    a.focus = crate::app::Focus::Left;
    let mk = |name: &str, mail: &str, logon: &str| {
        let mut h =
            Hit::bare(&format!("CN={name},OU=Staff,DC=example,DC=local"), EntryKind::User, name.into(), String::new());
        h.values.insert("mail".into(), vec![Value::Text(mail.into())]);
        h.values.insert("lastlogontimestamp".into(), vec![Value::Text(logon.into())]);
        h
    };
    let mut r = crate::app::ResultsView {
        title: "Users".into(),
        kind: crate::app::ResultsKind::Search { description: String::new() },
        kind_key: "users",
        list: HitList {
            hits: vec![
                mk("Bob", "zed@example.local", "0"),
                mk("Alice", "mid@example.local", "133520123450000000"),
                mk("Carol", "abc@example.local", "133000000000000000"),
            ],
            ..Default::default()
        },
        state: Default::default(),
        loading: None,
        started: std::time::Instant::now(),
        columns: vec!["mail".into(), "lastLogonTimestamp".into()],
        sort: (None, false),
        order: vec![],
        request: Some(crate::ldap::worker::Request::Search {
            base: "DC=example,DC=local".into(),
            scope: ldap3::Scope::Subtree,
            filter: "(objectClass=user)".into(),
            attrs: vec![],
        }),
        requested: vec!["mail".into(), "lastLogonTimestamp".into()],
        tree: None,
    };
    r.resort();
    r.state.select(Some(0));
    a.results = Some(r);
    a
}

#[test]
fn results_sort_cycles_and_reverses_with_header_arrows() {
    let mut a = results_with_values();
    let s = render(&mut a, 120, 40);
    assert!(s.contains("name ^"), "{s}");
    assert!(s.contains("1 column hidden"), "narrow pane drops the last column:\n{s}");
    let s = render(&mut a, 180, 40);
    assert!(s.contains("lastLogonTimestamp"), "{s}");
    let names = |a: &App| -> Vec<String> {
        let r = a.results.as_ref().unwrap();
        (0..3).map(|i| r.hit_at(i).unwrap().name.clone()).collect()
    };
    assert_eq!(names(&a), ["Alice", "Bob", "Carol"]);
    key(&mut a, 's');
    assert_eq!(names(&a), ["Carol", "Alice", "Bob"], "sorted by mail");
    let s = render(&mut a, 180, 40);
    assert!(s.contains("mail ^"), "{s}");
    key(&mut a, 's');
    assert_eq!(names(&a), ["Carol", "Alice", "Bob"], "chronological, never last");
    key(&mut a, 'S');
    assert_eq!(names(&a), ["Alice", "Carol", "Bob"], "descending keeps never last");
    let s = render(&mut a, 180, 40);
    assert!(s.contains("lastLogonTimestamp v"), "{s}");
    let s = render(&mut a, 120, 40);
    assert!(s.contains("sorted by lastLogonTimestamp"), "hidden sort column is named in the note:\n{s}");
    assert!(s.contains("never"), "decoded cell text:\n{s}");
    key(&mut a, 's');
    assert_eq!(names(&a), ["Alice", "Bob", "Carol"], "back to name");
}

#[test]
fn column_picker_reruns_search_for_new_attributes() {
    let mut a = results_with_values();
    key(&mut a, 'c');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("[x] mail") && s.contains("[ ] uidNumber"), "{s}");
    // Uncheck mail: no new attribute, so no re-run.
    key(&mut a, ' ');
    press(&mut a, KeyCode::Enter);
    let r = a.results.as_ref().unwrap();
    assert_eq!(r.columns, ["lastLogonTimestamp"]);
    assert!(r.loading.is_none());
    assert_eq!(a.columns_by_kind["users"], ["lastLogonTimestamp"]);
    // Add a typed attribute that was never fetched: the request is re-run with it.
    key(&mut a, 'c');
    key(&mut a, 'a');
    a.handle_event(Event::Paste("employeeID".into()));
    press(&mut a, KeyCode::Enter);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("[x] employeeID"), "{s}");
    press(&mut a, KeyCode::Enter);
    let r = a.results.as_ref().unwrap();
    assert!(r.loading.is_some(), "search should be re-running");
    assert!(r.requested.iter().any(|x| x == "employeeID"), "{:?}", r.requested);
    assert!(a.message.as_ref().unwrap().text.contains("employeeID"));
}

// ---------------------------------------------------------------------------------------------
// Membership tree (section 5.6.8)

#[test]
fn members_tree_expands_and_marks_cycles() {
    use crate::app::membertree::{Load, Row as MRow};
    use crate::ldap::model::{EntryKind, Hit, HitList};
    let mut a = browsing(jane());
    a.focus = crate::app::Focus::Left;
    let g = |dn: &str| Hit::bare(dn, EntryKind::Group, model::rdn_value(dn), String::new());
    let mut r = crate::app::ResultsView {
        title: "Members of everyone".into(),
        kind: crate::app::ResultsKind::Members { dn: "CN=everyone,OU=Groups,DC=example,DC=local".into() },
        kind_key: "other",
        list: HitList {
            hits: vec![
                g("CN=staff,OU=Groups,DC=example,DC=local"),
                Hit::bare("CN=Carol,OU=Staff,DC=example,DC=local", EntryKind::User, "Carol".into(), String::new()),
            ],
            ..Default::default()
        },
        state: Default::default(),
        loading: None,
        started: std::time::Instant::now(),
        columns: vec![],
        sort: (None, false),
        order: vec![],
        request: None,
        requested: vec![],
        tree: None,
    };
    r.resort();
    a.results = Some(r);
    key(&mut a, 't');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("tree of members"), "{s}");
    assert!(s.contains("- G everyone") && s.contains("+ G staff") && s.contains("  U Carol"), "{s}");
    // Expand staff: a request goes out and the row shows loading.
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Right);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("loading"), "{s}");
    let tree = a.results.as_mut().unwrap().tree.as_mut().unwrap();
    let staff = model::normalize_dn("CN=staff,OU=Groups,DC=example,DC=local");
    assert!(matches!(tree.get(&staff).unwrap().load, Load::Loading(_)));
    // Simulate the reply: staff contains everyone (cycle) and Alice.
    tree.set_children(
        &staff,
        vec![
            g("cn=Everyone,ou=Groups,dc=example,dc=local"),
            Hit::bare("CN=Alice,OU=Staff,DC=example,DC=local", EntryKind::User, "Alice".into(), String::new()),
        ],
    );
    let s = render(&mut a, 120, 40);
    assert!(s.contains("@ G everyone  (cycle)") || s.contains("@ G everyone (cycle)"), "{s}");
    assert!(s.contains("U Alice"), "{s}");
    // The cycle row cannot be expanded; the depth-limited rows are covered by unit tests.
    press(&mut a, KeyCode::Down);
    assert!(matches!(
        a.results.as_ref().unwrap().tree.as_ref().unwrap().selected_row(),
        Some(MRow::Node { cycle: true, .. })
    ));
    press(&mut a, KeyCode::Right);
    assert!(a.message.as_ref().unwrap().text.contains("cycle"));
    // y copies the selected node's DN; t goes back to the flat list.
    key(&mut a, 'y');
    assert_eq!(a.clipboard.as_deref(), Some("CN=everyone,OU=Groups,DC=example,DC=local"), "same node as the root");
    key(&mut a, 't');
    assert!(a.results.as_ref().unwrap().tree.is_none());
    let s = render(&mut a, 120, 40);
    assert!(!s.contains("tree of"), "{s}");
}

// ---------------------------------------------------------------------------------------------
// Export (section 5.6.1)

#[test]
fn export_entry_writes_file_and_confirms_overwrite() {
    let dir = std::env::temp_dir().join(format!("ldaptui-export-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut a = browsing(jane());
    a.profile.as_mut().unwrap().export.dir = Some(dir.to_string_lossy().into_owned());
    key(&mut a, 'e');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Export entry CN=Jane"), "{s}");
    assert!(s.contains("LDIF") && s.contains("JSON") && s.contains("CSV"), "{s}");
    assert!(s.contains("Jane.ldif"), "default name from the RDN:\n{s}");
    // Switch to JSON: the extension follows.
    press(&mut a, KeyCode::Up);
    press(&mut a, KeyCode::Right);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Jane.json"), "{s}");
    press(&mut a, KeyCode::Enter);
    assert!(a.overlay.is_none(), "dialog closes after writing");
    let path = dir.join("Jane.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["dn"], "CN=Jane,OU=Staff,DC=example,DC=local");
    assert_eq!(v["attributes"]["lastLogonTimestamp"][0], "never", "decoded by default");
    assert!(v["attributes"].get("uSNChanged").is_none(), "operational hidden unless o is on");
    assert!(a.message.as_ref().unwrap().text.contains("wrote 1 row"));
    // Same path again: first Enter asks, second overwrites.
    key(&mut a, 'e');
    press(&mut a, KeyCode::Up);
    press(&mut a, KeyCode::Right); // JSON again
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Down);
    key(&mut a, ' '); // decoded off
    press(&mut a, KeyCode::Enter);
    let s = render(&mut a, 120, 40);
    assert!(s.contains("file exists"), "{s}");
    press(&mut a, KeyCode::Enter);
    assert!(a.overlay.is_none());
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["attributes"]["lastLogonTimestamp"][0], "0", "raw when decoded is off");
    // Results export from the left pane.
    let mut a = results_with_values();
    a.profile.as_mut().unwrap().export.dir = Some(dir.to_string_lossy().into_owned());
    key(&mut a, 'e');
    let s = render(&mut a, 120, 40);
    assert!(s.contains("Export Users (3 rows)") && s.contains("LDIF is for whole entries"), "{s}");
    press(&mut a, KeyCode::Enter);
    let text = std::fs::read_to_string(dir.join("Users.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3);
    assert_eq!(v[0]["name"], "Alice", "display order");
    assert_eq!(v[0]["attributes"]["mail"][0], "mid@example.local");
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Mouse (section 5.6.6)

fn mouse(a: &mut App, kind: ratatui::crossterm::event::MouseEventKind, x: u16, y: u16) {
    use ratatui::crossterm::event::MouseEvent;
    a.handle_event(Event::Mouse(MouseEvent { kind, column: x, row: y, modifiers: KeyModifiers::NONE }));
}

fn find_cell(s: &str, needle: &str) -> (u16, u16) {
    for (y, line) in s.lines().enumerate() {
        if let Some(x) = line.find(needle) {
            return (line[..x].chars().count() as u16, y as u16);
        }
    }
    panic!("{needle:?} not on screen:\n{s}");
}

#[test]
fn mouse_clicks_select_sort_and_open_menus() {
    use ratatui::crossterm::event::{MouseButton, MouseEventKind};
    let mut a = results_with_values();
    let s = render(&mut a, 180, 40);
    // Click a result row: focus left, that row selected.
    let (x, y) = find_cell(&s, "U Carol");
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), x + 3, y);
    assert_eq!(a.focus, crate::app::Focus::Left);
    assert_eq!(a.results.as_ref().unwrap().selected_hit().unwrap().name, "Carol");
    // Click the mail header: sorted by mail; click again reverses.
    let (hx, hy) = find_cell(&s, "mail");
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), hx + 1, hy);
    let r = a.results.as_ref().unwrap();
    assert_eq!(r.sort, (Some("mail".into()), false));
    assert_eq!(r.hit_at(0).unwrap().name, "Carol");
    let s = render(&mut a, 180, 40);
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), hx + 1, hy);
    assert!(a.results.as_ref().unwrap().sort.1, "second click reverses");
    // Click an attribute row in the entry pane: focus right and selection follows.
    let (ex, ey) = find_cell(&s, "department");
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), ex + 2, ey);
    assert_eq!(a.focus, crate::app::Focus::Right);
    let (name, _) = a.entry.selected_value().unwrap();
    assert_eq!(name, "department");
    // Wheel over the entry pane moves its selection even while the left pane keeps focus.
    a.focus = crate::app::Focus::Left;
    mouse(&mut a, MouseEventKind::ScrollDown, ex + 2, ey);
    assert_eq!(a.focus, crate::app::Focus::Left, "wheel does not steal focus");
    let (name, _) = a.entry.selected_value().unwrap();
    assert_ne!(name, "department");
    // Right-click on the entry pane opens a context menu; Enter runs the highlighted item.
    mouse(&mut a, MouseEventKind::Down(MouseButton::Right), ex + 2, ey);
    let s = render(&mut a, 180, 40);
    assert!(s.contains("Copy entry DN") && s.contains("Mark for compare"), "{s}");
    let (mx, my) = find_cell(&s, "Copy entry DN");
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), mx, my);
    assert!(a.overlay.is_none());
    assert_eq!(a.clipboard.as_deref(), Some("CN=Jane,OU=Staff,DC=example,DC=local"));
    // Footer hint click acts like the key: "c columns" opens the picker.
    a.focus = crate::app::Focus::Left;
    let s = render(&mut a, 180, 40);
    let (fx, fy) = find_cell(&s, "c columns");
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), fx, fy);
    assert!(matches!(a.overlay, Some(crate::app::Overlay::Columns { .. })));
    // Clicking a picker row toggles it.
    let s = render(&mut a, 180, 40);
    let (cx, cy) = find_cell(&s, "[x] mail");
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), cx + 5, cy);
    let s = render(&mut a, 180, 40);
    assert!(s.contains("[ ] mail"), "{s}");
}

#[test]
fn mouse_tree_arrow_expands_without_opening() {
    use crate::app::tree::Load;
    use ratatui::crossterm::event::{MouseButton, MouseEventKind};
    let mut a = browsing(jane());
    a.focus = crate::app::Focus::Left;
    a.tree = crate::app::tree::Tree::new(&["DC=example,DC=local".into()], 100);
    let root = crate::app::tree::key_of("DC=example,DC=local");
    a.tree.get_mut(&root).unwrap().expanded = true;
    a.tree.set_children(
        &root,
        crate::ldap::model::ChildList {
            children: vec![crate::ldap::model::Child {
                dn: "OU=Staff,DC=example,DC=local".into(),
                kind: crate::ldap::model::EntryKind::OrgUnit,
                has_children: Some(true),
            }],
            ..Default::default()
        },
    );
    let s = render(&mut a, 120, 40);
    let (x, y) = find_cell(&s, "+ O OU=Staff");
    let before = a.entry.want.clone();
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), x, y);
    let staff = crate::app::tree::key_of("OU=Staff,DC=example,DC=local");
    let n = a.tree.get(&staff).unwrap();
    assert!(n.expanded, "arrow click expands");
    assert!(matches!(n.load, Load::Loading(_)), "and starts loading");
    assert_eq!(a.entry.want, before, "without requesting the entry");
    assert_eq!(a.tree.selected_key(), Some(&root), "selection unchanged");
    // Click on the label selects and requests the entry.
    mouse(&mut a, MouseEventKind::Down(MouseButton::Left), x + 6, y);
    assert_eq!(a.tree.selected_key(), Some(&staff));
    assert!(a.entry.want.as_ref().is_some_and(|(dn, _)| dn.contains("OU=Staff")));
}

#[test]
fn hints_at_positions_match_rendering() {
    let ctx = super::Ctx { theme: super::Theme::detect(), sym: super::Symbols::pick(true) };
    let area = ratatui::layout::Rect::new(0, 5, 80, 1);
    let (line, areas) = super::hints_at(&[("↑↓", "move"), ("Enter", "open"), ("c", "columns")], &ctx, area);
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    assert_eq!(areas.len(), 3);
    for (r, k) in &areas {
        let at = text.chars().skip(r.x as usize).take(r.width as usize).collect::<String>();
        assert!(at.starts_with(k.as_str()), "{k:?} expected at {}, found {at:?} in {text:?}", r.x);
        assert_eq!(r.y, 5);
    }
}
