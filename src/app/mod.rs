//! Application state and the logic that ties UI actions to LDAP requests.

pub mod columns;
pub mod diff;
pub mod export;
pub mod history;
pub mod input;
mod keys;
pub mod membertree;
pub mod mouse;
pub mod tree;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ldap3::Scope;
use ratatui::widgets::{ListState, TableState};
use secrecy::SecretString;
use tracing::{info, warn};

use crate::config::{Bookmark, Config, Profile, SavedSearch, Scheme};
use crate::ldap::error::{ErrorKind, Failure};
use crate::ldap::flavor::{self, Flavor};
use crate::ldap::model::{self, Entry, EntryKind, Hit, HitList, Value};
use crate::ldap::session::{ConnInfo, Creds};
use crate::ldap::worker::{Reply, Request, RequestId, Response, Worker};
use crate::ldap::{decode, filter};
use crate::secrets::{Resolution, Secrets};

use history::SearchHistory;
use input::TextInput;
use tree::{Key, Load, Tree, key_of};

pub const MAX_LOGIN_ATTEMPTS: u32 = 3;
const ENTRY_DEBOUNCE: Duration = Duration::from_millis(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub text: String,
    pub level: Level,
    pub at: Instant,
}

pub struct LoginForm {
    pub profile: Profile,
    pub dn: TextInput,
    pub password: TextInput,
    pub dn_editable: bool,
    /// 0 = DN field, 1 = password field.
    pub field: usize,
    pub attempt: u32,
    pub error: Option<String>,
}

pub enum Screen {
    Picker { state: ListState },
    Login(Box<LoginForm>),
    Connecting { profile: Box<Profile>, request: RequestId, started: Instant, attempt: u32 },
    Browse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchKind {
    Users,
    Groups,
    Dn,
    Attribute,
    Raw,
    Saved,
}

impl SearchKind {
    pub const ALL: [SearchKind; 6] = [
        SearchKind::Users,
        SearchKind::Groups,
        SearchKind::Dn,
        SearchKind::Attribute,
        SearchKind::Raw,
        SearchKind::Saved,
    ];

    /// Stable key used in the history file.
    pub fn key(self) -> &'static str {
        match self {
            SearchKind::Users => "users",
            SearchKind::Groups => "groups",
            SearchKind::Dn => "dn",
            SearchKind::Attribute => "attribute",
            SearchKind::Raw => "raw",
            SearchKind::Saved => "saved",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SearchKind::Users => "Users",
            SearchKind::Groups => "Groups",
            SearchKind::Dn => "DN",
            SearchKind::Attribute => "Attribute",
            SearchKind::Raw => "Raw filter",
            SearchKind::Saved => "Saved",
        }
    }

    pub fn prompt(self) -> &'static str {
        match self {
            SearchKind::Users => "Name, username or email (substring match)",
            SearchKind::Groups => "Group name (substring match)",
            SearchKind::Dn => "Distinguished name, e.g. CN=Jane Doe,OU=Staff,DC=example,DC=local",
            SearchKind::Attribute => "attribute=value   (* is a wildcard; also >=  <=  ~=)",
            SearchKind::Raw => "LDAP filter, e.g. (&(objectClass=user)(department=IT))",
            SearchKind::Saved => "Enter run · e edit as raw filter · d delete · r rename",
        }
    }
}

pub const SCOPES: [(Scope, &str); 3] =
    [(Scope::Subtree, "subtree"), (Scope::OneLevel, "one level"), (Scope::Base, "base")];

/// History recall in progress in the query field (`↑`/`↓`).
pub struct Recall {
    pub items: Vec<String>,
    pub pos: usize,
    /// What was typed before recall started, restored when stepping past the newest entry.
    pub typed: String,
}

/// A small prompt layered over the search dialog.
pub enum SubPrompt {
    /// `Ctrl-S`: name the current search; `shared` stores it at the top level of config.json.
    Save { name: TextInput, shared: bool },
    /// `r` on the Saved tab.
    Rename { index: usize, name: TextInput },
}

pub struct SearchForm {
    pub kind: SearchKind,
    pub query: TextInput,
    pub base: TextInput,
    pub scope: usize,
    /// 0 = kind, 1 = query (or the saved list), 2 = base, 3 = scope
    pub field: usize,
    pub error: Option<String>,
    pub recall: Option<Recall>,
    /// Selection in the Saved tab.
    pub saved_sel: usize,
    /// A saved search with `{q}` waiting for its text: (name, filter).
    pub template: Option<(String, String)>,
    pub sub: Option<SubPrompt>,
}

impl SearchForm {
    /// Whether the Saved tab's list is showing (rather than a text prompt).
    pub fn showing_saved_list(&self) -> bool {
        self.kind == SearchKind::Saved && self.template.is_none()
    }

    pub fn field_count(&self) -> usize {
        if self.showing_saved_list() { 2 } else { 4 }
    }
}

pub enum Overlay {
    Help {
        scroll: u16,
    },
    Error {
        failure: Failure,
        scroll: u16,
    },
    Value {
        title: String,
        lines: Vec<String>,
        scroll: u16,
    },
    Goto {
        input: TextInput,
        error: Option<String>,
    },
    Search(Box<SearchForm>),
    Filter {
        key: Key,
        input: TextInput,
    },
    /// Live attribute-name filter for the entry pane (rendered inline, not as a popup).
    AttrFilter {
        input: TextInput,
    },
    Diff(Box<diff::DiffView>),
    /// `B` on an unbookmarked DN: name it.
    BookmarkAdd {
        dn: String,
        input: TextInput,
    },
    /// `'`: the bookmark list. `rename` holds the input while renaming the selected one.
    Bookmarks {
        state: ListState,
        rename: Option<TextInput>,
    },
    /// `c` on results: choose and order columns. `adding` holds the input for a typed attribute.
    Columns {
        items: Vec<(String, bool)>,
        state: ListState,
        adding: Option<TextInput>,
    },
    /// `e`: export what is in focus.
    Export(Box<ExportForm>),
    /// Right-click context menu.
    Menu(Box<mouse::Menu>),
}

pub struct ExportForm {
    pub what: export::What,
    /// Index into `what.formats()`.
    pub format: usize,
    pub path: TextInput,
    pub decoded: bool,
    /// 0 = format, 1 = path, 2 = decoded
    pub field: usize,
    pub error: Option<String>,
    pub note: Option<String>,
    /// Set after Enter on an existing file; a second Enter overwrites.
    pub confirm: bool,
}

impl ExportForm {
    pub fn format(&self) -> export::Format {
        self.what.formats()[self.format.min(self.what.formats().len() - 1)]
    }

    /// Switches format, updating the file extension when the path still has the old one.
    pub fn set_format(&mut self, i: usize) {
        let old = self.format().extension();
        self.format = i % self.what.formats().len();
        let new = self.format().extension();
        let p = self.path.text().to_string();
        if let Some(stem) = p.strip_suffix(&format!(".{old}")) {
            self.path.set(&format!("{stem}.{new}"));
        }
        self.confirm = false;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResultsKind {
    Search { description: String },
    Members { dn: String },
    MemberOf { dn: String, nested: bool },
}

pub struct ResultsView {
    pub title: String,
    pub kind: ResultsKind,
    /// `users`, `groups` or `other`: which column defaults apply.
    pub kind_key: &'static str,
    pub list: HitList,
    /// Selection as a display index (into `order`).
    pub state: TableState,
    pub loading: Option<RequestId>,
    pub started: Instant,
    /// Attribute columns after the name column.
    pub columns: Vec<String>,
    /// Sort column (`None` = name) and direction.
    pub sort: (Option<String>, bool),
    /// Display order: indices into `list.hits`.
    pub order: Vec<usize>,
    /// The request that produced the list, re-run when new columns need more attributes.
    pub request: Option<Request>,
    /// Extra attributes the request asked for.
    pub requested: Vec<String>,
    /// `t`: the members / memberOf list shown as a lazily expanded tree.
    pub tree: Option<membertree::MemberTree>,
}

impl ResultsView {
    pub fn resort(&mut self) {
        self.order = columns::sort_order(&self.list.hits, self.sort.0.as_deref(), self.sort.1);
    }

    /// The hit shown at display row `i`.
    pub fn hit_at(&self, i: usize) -> Option<&Hit> {
        self.list.hits.get(*self.order.get(i)?)
    }

    pub fn selected_hit(&self) -> Option<&Hit> {
        self.hit_at(self.state.selected()?)
    }

    /// Keeps the same hit selected across a re-sort.
    fn reselect(&mut self, hit_index: Option<usize>) {
        let pos = hit_index.and_then(|h| self.order.iter().position(|&i| i == h));
        self.state.select(pos.or_else(|| (!self.order.is_empty()).then_some(0)));
    }

    /// `s`: name → first column → … → name.
    pub fn cycle_sort(&mut self) {
        let cur = self.selected_hit_index();
        let next = match &self.sort.0 {
            None => self.columns.first().cloned(),
            Some(c) => {
                let i = self.columns.iter().position(|x| x.eq_ignore_ascii_case(c));
                i.and_then(|i| self.columns.get(i + 1).cloned())
            }
        };
        self.sort = (next, false);
        self.resort();
        self.reselect(cur);
    }

    pub fn reverse_sort(&mut self) {
        let cur = self.selected_hit_index();
        self.sort.1 = !self.sort.1;
        self.resort();
        self.reselect(cur);
    }

    /// `None` = name column, else index into `columns`.
    pub fn sort_by_column(&mut self, col: Option<usize>) {
        let cur = self.selected_hit_index();
        let name = col.and_then(|i| self.columns.get(i).cloned());
        if self.sort.0.as_deref().map(|s| s.to_ascii_lowercase()) == name.as_deref().map(|s| s.to_ascii_lowercase()) {
            self.sort.1 = !self.sort.1;
        } else {
            self.sort = (name, false);
        }
        self.resort();
        self.reselect(cur);
    }

    fn selected_hit_index(&self) -> Option<usize> {
        self.order.get(self.state.selected()?).copied()
    }

    pub fn sort_label(&self) -> String {
        format!("{}{}", self.sort.0.clone().unwrap_or_else(|| "name".into()), if self.sort.1 { " ↓" } else { " ↑" })
    }
}

#[derive(Default)]
pub struct EntryView {
    pub dn: Option<String>,
    pub entry: Option<Entry>,
    pub loading: Option<RequestId>,
    pub error: Option<Failure>,
    pub state: TableState,
    pub show_operational: bool,
    /// Case-insensitive substring filter on attribute names; kept across entries until cleared.
    pub filter: Option<String>,
    /// Requested DN and when, for debouncing tree movement.
    pub want: Option<(String, Instant)>,
}

/// A row of the entry table: (attribute index, value index).
pub type EntryRow = (usize, usize);

impl EntryView {
    pub fn rows(&self) -> Vec<EntryRow> {
        let Some(e) = &self.entry else { return vec![] };
        e.attrs
            .iter()
            .enumerate()
            .filter(|(_, a)| self.show_operational || !a.operational)
            .filter(|(_, a)| attr_matches(self.filter.as_deref(), &a.name))
            .flat_map(|(ai, a)| (0..a.values.len().max(1)).map(move |vi| (ai, vi)))
            .collect()
    }

    /// Number of attributes shown and the number that would be shown without the filter.
    pub fn filter_counts(&self) -> (usize, usize) {
        let Some(e) = &self.entry else { return (0, 0) };
        let visible = e.attrs.iter().filter(|a| self.show_operational || !a.operational);
        let total = visible.clone().count();
        let shown = visible.filter(|a| attr_matches(self.filter.as_deref(), &a.name)).count();
        (shown, total)
    }

    /// Applies a new filter text (empty clears) and moves the selection to the top.
    pub fn set_filter(&mut self, text: &str) {
        let text = text.trim();
        self.filter = (!text.is_empty()).then(|| text.to_string());
        self.state.select(Some(0));
    }

    pub fn selected_value(&self) -> Option<(&str, &Value)> {
        let rows = self.rows();
        let (ai, vi) = *rows.get(self.state.selected()?)?;
        let a = &self.entry.as_ref()?.attrs[ai];
        Some((&a.name, a.values.get(vi)?))
    }

    /// The DN in the selected row, if it is followable.
    pub fn selected_dn(&self) -> Option<String> {
        let (name, v) = self.selected_value()?;
        match v {
            Value::Text(s) if is_followable(name, s) => Some(s.clone()),
            _ => None,
        }
    }
}

/// Case-insensitive substring match of an attribute name against an optional filter.
pub fn attr_matches(filter: Option<&str>, name: &str) -> bool {
    match filter {
        None => true,
        Some(f) => name.to_ascii_lowercase().contains(&f.to_ascii_lowercase()),
    }
}

pub fn is_followable(attr: &str, value: &str) -> bool {
    (flavor::is_dn_attribute(attr) || model::looks_like_dn(value)) && model::looks_like_dn(value)
}

#[derive(Default)]
pub struct History {
    pub back: Vec<String>,
    pub forward: Vec<String>,
    pub current: Option<String>,
}

impl History {
    pub fn visit(&mut self, dn: &str) {
        if self.current.as_deref().is_some_and(|c| model::dn_eq(c, dn)) {
            return;
        }
        if let Some(c) = self.current.take() {
            self.back.push(c);
            if self.back.len() > 200 {
                self.back.remove(0);
            }
        }
        self.forward.clear();
        self.current = Some(dn.to_string());
    }

    pub fn go_back(&mut self) -> Option<String> {
        let prev = self.back.pop()?;
        if let Some(c) = self.current.replace(prev.clone()) {
            self.forward.push(c);
        }
        Some(prev)
    }

    pub fn go_forward(&mut self) -> Option<String> {
        let next = self.forward.pop()?;
        if let Some(c) = self.current.replace(next.clone()) {
            self.back.push(c);
        }
        Some(next)
    }
}

enum Pending {
    Children {
        key: Key,
        started: Instant,
    },
    Entry,
    Results,
    /// Refresh of the entry marked for comparison.
    Compare,
    /// Children of a membership-tree node.
    TreeNode {
        key: String,
    },
}

pub struct App {
    pub config: Config,
    pub secrets: Secrets,
    pub ascii: bool,
    pub screen: Screen,
    pub overlay: Option<Overlay>,
    pub profile: Option<Profile>,
    pub conn: Option<ConnInfo>,
    creds: Option<Creds>,
    pub focus: Focus,
    pub tree: Tree,
    pub tree_state: ListState,
    pub results: Option<ResultsView>,
    pub entry: EntryView,
    pub history: History,
    /// Entry marked with `d` for comparison.
    pub compare: Option<Entry>,
    pub message: Option<Message>,
    pub search_history: SearchHistory,
    /// Columns chosen this session, per result kind (`users`, `groups`, `other`).
    pub columns_by_kind: HashMap<String, Vec<String>>,
    pub last_search_kind: SearchKind,
    pub disconnected: bool,
    pub tick: usize,
    pub should_quit: bool,
    worker: Worker,
    pending: HashMap<RequestId, Pending>,
    reveal: Option<String>,
    /// Last profile the user tried to connect to (re-selected in the picker).
    attempted: Option<String>,
    /// Clipboard text queued for the terminal (written by the main loop between frames).
    pub clipboard: Option<String>,
    /// Screen areas from the last draw, for mouse hit-testing.
    pub hit: mouse::HitAreas,
    pub last_click: Option<(Instant, u16, u16)>,
}

impl App {
    pub fn new(config: Config, secrets: Secrets, ascii: bool, warnings: Vec<String>) -> App {
        let mut state = ListState::default();
        let default_idx = config
            .default_profile
            .as_ref()
            .and_then(|d| config.profile_names().iter().position(|n| n == d))
            .unwrap_or(0);
        state.select(Some(default_idx));
        let mut app = App {
            config,
            secrets,
            ascii,
            screen: Screen::Picker { state },
            overlay: None,
            profile: None,
            conn: None,
            creds: None,
            focus: Focus::Left,
            tree: Tree::default(),
            tree_state: ListState::default(),
            results: None,
            entry: EntryView::default(),
            history: History::default(),
            compare: None,
            message: None,
            search_history: SearchHistory::default(),
            columns_by_kind: HashMap::new(),
            last_search_kind: SearchKind::Users,
            disconnected: false,
            tick: 0,
            should_quit: false,
            worker: Worker::spawn(),
            pending: HashMap::new(),
            reveal: None,
            attempted: None,
            clipboard: None,
            hit: mouse::HitAreas::default(),
            last_click: None,
        };
        if !warnings.is_empty() {
            app.set_message(warnings.join("; "), Level::Warn);
        }
        app
    }

    pub fn set_message(&mut self, text: impl Into<String>, level: Level) {
        let text = text.into();
        match level {
            Level::Error => warn!("{text}"),
            _ => info!("{text}"),
        }
        self.message = Some(Message { text, level, at: Instant::now() });
    }

    /// Loads the persisted search history; without this, history stays in memory only.
    pub fn load_history(&mut self, path: std::path::PathBuf) {
        self.search_history = SearchHistory::load(path);
    }

    fn profile_name(&self) -> String {
        self.profile.as_ref().map(|p| p.name.clone()).unwrap_or_default()
    }

    pub fn show_error(&mut self, f: Failure) {
        warn!(kind = ?f.kind, detail = %f.detail, "{}", f.title);
        self.set_message(f.title.clone(), Level::Error);
        self.overlay = Some(Overlay::Error { failure: f, scroll: 0 });
    }

    pub fn flavor(&self) -> Flavor {
        self.conn.as_ref().map(|c| c.flavor).unwrap_or(Flavor::Generic)
    }

    // -----------------------------------------------------------------------------------------
    // Connection lifecycle

    /// Starts connecting to a profile, prompting for credentials if needed.
    pub fn start_profile(&mut self, name: &str) {
        self.attempted = Some(name.to_string());
        let Some(profile) = self.config.profile(name).cloned() else {
            self.set_message(format!("unknown profile \"{name}\""), Level::Error);
            return;
        };
        match self.secrets.resolve(&profile) {
            Resolution::Anonymous => self.connect(profile, Creds::Anonymous, 1),
            Resolution::Ready { bind_dn, password } => self.connect(profile, Creds::Simple { bind_dn, password }, 1),
            Resolution::NeedPassword { bind_dn } => self.show_login(profile, Some(bind_dn), 1, None),
            Resolution::NeedBoth => self.show_login(profile, None, 1, None),
        }
    }

    fn show_login(&mut self, profile: Profile, bind_dn: Option<String>, attempt: u32, error: Option<String>) {
        let dn_editable = bind_dn.is_none();
        self.screen = Screen::Login(Box::new(LoginForm {
            profile,
            dn: TextInput::new(bind_dn.as_deref().unwrap_or("")),
            password: TextInput::masked(),
            dn_editable,
            field: if dn_editable { 0 } else { 1 },
            attempt,
            error,
        }));
    }

    pub fn submit_login(&mut self, anonymous: bool) {
        let Screen::Login(form) = std::mem::replace(&mut self.screen, Screen::Browse) else { return };
        let creds = if anonymous {
            Creds::Anonymous
        } else {
            Creds::Simple {
                bind_dn: form.dn.text().trim().to_string(),
                password: SecretString::from(form.password.text().to_string()),
            }
        };
        if let Creds::Simple { bind_dn, .. } = &creds
            && bind_dn.is_empty()
        {
            let mut form = form;
            form.error = Some("Enter a bind DN or username".into());
            self.screen = Screen::Login(form);
            return;
        }
        self.connect(form.profile, creds, form.attempt);
    }

    fn connect(&mut self, profile: Profile, creds: Creds, attempt: u32) {
        self.pending.clear();
        self.creds = Some(creds.clone());
        let request = self.worker.send(Request::Connect { profile: Box::new(profile.clone()), creds });
        self.screen = Screen::Connecting { profile: Box::new(profile), request, started: Instant::now(), attempt };
    }

    pub fn reconnect(&mut self) {
        let (Some(p), Some(c)) = (self.profile.clone(), self.creds.clone()) else { return };
        self.set_message("reconnecting…", Level::Info);
        let request = self.worker.send(Request::Connect { profile: Box::new(p.clone()), creds: c });
        self.pending.clear();
        self.screen =
            Screen::Connecting { profile: Box::new(p), request, started: Instant::now(), attempt: MAX_LOGIN_ATTEMPTS };
    }

    pub fn back_to_picker(&mut self) {
        self.worker.send(Request::Disconnect);
        self.pending.clear();
        self.conn = None;
        self.creds = None;
        self.results = None;
        self.entry = EntryView::default();
        self.compare = None;
        self.overlay = None;
        let names = self.config.profile_names();
        let mut state = ListState::default();
        let current = self.attempted.clone().or_else(|| self.profile.as_ref().map(|p| p.name.clone()));
        let idx = current.and_then(|c| names.iter().position(|n| *n == c)).unwrap_or(0);
        state.select(Some(idx));
        self.screen = Screen::Picker { state };
    }

    fn on_connected(&mut self, profile: Profile, info: ConnInfo) {
        let same_profile = self.profile.as_ref().is_some_and(|p| p.name == profile.name) && self.conn.is_some();
        let mut roots = vec![info.base_dn.clone()];
        if profile.show_all_naming_contexts {
            for nc in &info.naming_contexts {
                if !roots.iter().any(|r| model::dn_eq(r, nc)) {
                    roots.push(nc.clone());
                }
            }
        }
        let insecure = profile.scheme == Scheme::Ldaps && profile.insecure_skip_verify;
        let plain_bind = profile.scheme == Scheme::Ldap && info.bound_as.is_some();
        if !same_profile {
            self.tree = Tree::new(&roots, profile.tree_child_limit);
            self.history = History::default();
            self.results = None;
            self.entry = EntryView::default();
            self.compare = None;
            self.focus = Focus::Left;
        }
        self.profile = Some(profile);
        self.conn = Some(info);
        self.disconnected = false;
        self.screen = Screen::Browse;
        self.overlay = None;
        let mut msg = format!("connected ({})", self.flavor().label());
        let mut level = Level::Info;
        if insecure {
            msg.push_str(" — TLS certificate NOT verified");
            level = Level::Warn;
        }
        if plain_bind {
            msg.push_str(" — password was sent unencrypted (plain LDAP)");
            level = Level::Warn;
        }
        self.set_message(msg, level);
        if same_profile {
            // Reload what was on screen.
            let expanded: Vec<Key> =
                self.tree.nodes.iter().filter(|(_, n)| n.expanded).map(|(k, _)| k.clone()).collect();
            for k in expanded {
                self.load_children(&k);
            }
            if let Some(dn) = self.entry.dn.clone() {
                self.request_entry(&dn);
            }
        } else if let Some(root) = self.tree.roots.first().cloned() {
            self.tree.get_mut(&root).expect("root").expanded = true;
            self.load_children(&root);
            let dn = self.tree.get(&root).expect("root").dn.clone();
            self.request_entry(&dn);
            self.history.visit(&dn);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Requests

    pub fn load_children(&mut self, k: &str) {
        let Some(n) = self.tree.get(k) else { return };
        if n.referral.is_some() {
            return;
        }
        let (dn, prefix, limit, load) = (n.dn.clone(), n.prefix.clone(), n.limit, n.load.clone());
        if let Load::Loading(old) = load {
            self.cancel(old);
        }
        let id = self.worker.send(Request::Children { dn, prefix, limit });
        self.pending.insert(id, Pending::Children { key: k.to_string(), started: Instant::now() });
        if let Some(n) = self.tree.get_mut(k) {
            n.load = Load::Loading(id);
        }
    }

    pub fn request_entry(&mut self, dn: &str) {
        if let Some(old) = self.entry.loading.take() {
            self.cancel(old);
        }
        self.entry.want = None;
        let same = self.entry.dn.as_deref().is_some_and(|d| model::dn_eq(d, dn));
        if !same {
            self.entry.entry = None;
            self.entry.state = TableState::default();
        }
        self.entry.dn = Some(dn.to_string());
        self.entry.error = None;
        let id = self.worker.send(Request::Entry { dn: dn.to_string() });
        self.pending.insert(id, Pending::Entry);
        self.entry.loading = Some(id);
    }

    /// Requests an entry after a short delay, so scrolling the tree doesn't flood the server.
    pub fn want_entry(&mut self, dn: &str) {
        if self.entry.dn.as_deref().is_some_and(|d| model::dn_eq(d, dn)) && self.entry.want.is_none() {
            return;
        }
        self.entry.want = Some((dn.to_string(), Instant::now()));
    }

    /// Columns for a result kind: chosen this session, else the profile's config, else flavor defaults.
    pub fn columns_for(&self, kind_key: &str) -> Vec<String> {
        if let Some(c) = self.columns_by_kind.get(kind_key) {
            return c.clone();
        }
        if let Some(c) = self.profile.as_ref().and_then(|p| p.results.columns.get(kind_key)) {
            return c.clone();
        }
        columns::default_columns(self.flavor(), kind_key)
    }

    fn start_results(&mut self, title: String, kind: ResultsKind, kind_key: &'static str, req: Request) {
        if let Some(old) = self.results.as_ref().and_then(|r| r.loading) {
            self.cancel(old);
        }
        let cols = self.columns_for(kind_key);
        let requested = columns::needed_attrs(&cols);
        let req = req.with_attrs(requested.clone());
        let sort = self
            .results
            .as_ref()
            .filter(|r| r.kind_key == kind_key)
            .map(|r| r.sort.clone())
            .or_else(|| self.profile.as_ref().and_then(|p| p.results.sort.as_deref()).map(columns::parse_sort))
            .unwrap_or((None, false));
        let id = self.worker.send(req.clone());
        self.pending.insert(id, Pending::Results);
        self.results = Some(ResultsView {
            title,
            kind,
            kind_key,
            list: HitList::default(),
            state: TableState::default(),
            loading: Some(id),
            started: Instant::now(),
            columns: cols,
            sort,
            order: Vec::new(),
            request: Some(req),
            requested,
            tree: None,
        });
        self.focus = Focus::Left;
    }

    // -----------------------------------------------------------------------------------------
    // Membership tree

    /// `t` in a members / memberOf view: switches between the flat list and the tree.
    pub fn toggle_member_tree(&mut self) {
        let Some(r) = self.results.as_mut() else { return };
        if r.tree.is_some() {
            r.tree = None;
            r.state.select((!r.order.is_empty()).then_some(0));
            return;
        }
        let (direction, dn) = match &r.kind {
            ResultsKind::Members { dn } => (membertree::Direction::Members, dn.clone()),
            ResultsKind::MemberOf { dn, .. } => (membertree::Direction::MemberOf, dn.clone()),
            ResultsKind::Search { .. } => {
                self.set_message("the tree view is for members and groups lists (m / M)", Level::Info);
                return;
            }
        };
        if r.loading.is_some() {
            return;
        }
        let kind = match direction {
            membertree::Direction::Members => EntryKind::Group,
            membertree::Direction::MemberOf => self.entry.entry.as_ref().map(|e| e.kind()).unwrap_or(EntryKind::Other),
        };
        let root = Hit::bare(&dn, kind, model::rdn_value(&dn), String::new());
        // Direct rows only: the tree shows how nested memberships arise.
        let children: Vec<Hit> = r
            .order
            .iter()
            .filter_map(|&i| r.list.hits.get(i))
            .filter(|h| h.tag.as_deref() != Some("nested"))
            .cloned()
            .collect();
        r.tree = Some(membertree::MemberTree::new(direction, root, children));
    }

    /// Expands a tree node, loading its members / groups on first use.
    pub fn expand_tree_node(&mut self, key: &str) {
        let Some(r) = self.results.as_mut() else { return };
        let Some(t) = r.tree.as_mut() else { return };
        let Some(n) = t.get(key) else { return };
        if !t.expandable(n) {
            return;
        }
        let (dn, load) = (n.hit.dn.clone(), n.load.clone());
        let direction = t.direction;
        if let membertree::Load::Loading(_) = load {
            return;
        }
        t.get_mut(key).expect("node").expanded = true;
        if matches!(load, membertree::Load::NotLoaded | membertree::Load::Failed(_)) {
            let req = match direction {
                membertree::Direction::Members => Request::Members { dn, attrs: vec![] },
                membertree::Direction::MemberOf => Request::MemberOf { dn, nested: false, attrs: vec![] },
            };
            let id = self.worker.send(req);
            self.pending.insert(id, Pending::TreeNode { key: key.to_string() });
            if let Some(t) = self.results.as_mut().and_then(|r| r.tree.as_mut())
                && let Some(n) = t.get_mut(key)
            {
                n.load = membertree::Load::Loading(id);
            }
        }
    }

    /// `r` on a tree node: reload it.
    pub fn reload_tree_node(&mut self, key: &str) {
        let mut in_flight = None;
        if let Some(t) = self.results.as_mut().and_then(|r| r.tree.as_mut())
            && let Some(n) = t.get_mut(key)
        {
            if let membertree::Load::Loading(id) = n.load {
                in_flight = Some(id);
            }
            n.load = membertree::Load::NotLoaded;
        }
        if let Some(id) = in_flight {
            self.cancel(id);
        }
        self.expand_tree_node(key);
    }

    /// `c` on results: opens the column picker.
    pub fn open_columns(&mut self) {
        let Some(r) = &self.results else { return };
        let mut items: Vec<(String, bool)> = r.columns.iter().map(|c| (c.clone(), true)).collect();
        for c in columns::candidates(self.flavor()) {
            if !items.iter().any(|(x, _)| x.eq_ignore_ascii_case(&c)) {
                items.push((c, false));
            }
        }
        let mut state = ListState::default();
        state.select(Some(0));
        self.overlay = Some(Overlay::Columns { items, state, adding: None });
    }

    /// Applies a new column list to the results, re-running the request if it needs attributes
    /// that were not fetched.
    pub fn apply_columns(&mut self, cols: Vec<String>) {
        let Some(r) = self.results.as_mut() else { return };
        self.columns_by_kind.insert(r.kind_key.to_string(), cols.clone());
        let needed = columns::needed_attrs(&cols);
        let fetched = |a: &String| {
            r.requested.iter().any(|x| x.eq_ignore_ascii_case(a))
                || ["objectclass", "cn", "displayname", "name", "uid", "samaccountname", "mail", "description", "ou"]
                    .contains(&a.to_ascii_lowercase().as_str())
        };
        let missing: Vec<String> = needed.iter().filter(|a| !fetched(a)).cloned().collect();
        r.columns = cols;
        if r.sort.0.as_ref().is_some_and(|s| !r.columns.iter().any(|c| c.eq_ignore_ascii_case(s))) {
            r.sort = (None, false);
        }
        if missing.is_empty() || r.list.hits.is_empty() {
            let cur = r.selected_hit_index();
            r.resort();
            r.reselect(cur);
            return;
        }
        let (title, kind, kind_key, req) = (r.title.clone(), r.kind.clone(), r.kind_key, r.request.clone());
        let Some(req) = req else { return };
        self.set_message(format!("re-running the search to fetch {}", missing.join(", ")), Level::Info);
        self.start_results(title, kind, kind_key, req);
    }

    pub fn cancel(&mut self, id: RequestId) {
        if self.pending.remove(&id).is_some() {
            self.worker.send(Request::Cancel { target: id });
        }
    }

    /// Esc while something is loading: cancel the most visible operation.
    pub fn cancel_current(&mut self) -> bool {
        if let Some(id) = self.results.as_ref().and_then(|r| r.loading) {
            self.cancel(id);
            if let Some(r) = self.results.as_mut() {
                r.loading = None;
                r.list.warning = Some("cancelled".into());
            }
            self.set_message("search cancelled", Level::Info);
            return true;
        }
        false
    }

    pub fn run_search(&mut self, form: &SearchForm) -> Result<(), String> {
        let q = form.query.text().trim().to_string();
        if q.is_empty() {
            return Err("enter something to search for".into());
        }
        let profile = self.profile.clone().ok_or("not connected")?;
        let base = form.base.text().trim().to_string();
        let base =
            if base.is_empty() { self.conn.as_ref().map(|c| c.base_dn.clone()).unwrap_or_default() } else { base };
        let scope = SCOPES[form.scope].0;
        let flavor = self.flavor();
        if let Some((name, template)) = &form.template {
            let filter = template.replace("{q}", &filter::escape(&q));
            filter::validate(&filter).map_err(|e| e.to_string())?;
            info!(%filter, %base, "saved search");
            self.remember_search(SearchKind::Saved, &q);
            self.start_results(
                format!("{name} — \"{q}\""),
                ResultsKind::Search { description: filter.clone() },
                "other",
                Request::Search { base, scope, filter, attrs: vec![] },
            );
            return Ok(());
        }
        let (filter, desc) = match form.kind {
            SearchKind::Users => (flavor::user_filter(&profile, flavor, &q), format!("users matching \"{q}\"")),
            SearchKind::Groups => (flavor::group_filter(&profile, flavor, &q), format!("groups matching \"{q}\"")),
            SearchKind::Attribute => (filter::attribute_filter(&q).map_err(|e| e.to_string())?, q.clone()),
            SearchKind::Raw => (filter::raw_filter(&q).map_err(|e| e.to_string())?, q.clone()),
            SearchKind::Saved => return Err("select a saved search and press Enter".into()),
            SearchKind::Dn => {
                if !model::looks_like_dn(&q) {
                    return Err("that doesn't look like a DN (expected attr=value,attr=value…)".into());
                }
                self.remember_search(SearchKind::Dn, &q);
                self.start_results(
                    format!("DN {q}"),
                    ResultsKind::Search { description: q.clone() },
                    "other",
                    Request::FindDn { dn: q.clone(), attrs: vec![] },
                );
                return Ok(());
            }
        };
        info!(%filter, %base, "search");
        self.remember_search(form.kind, &q);
        self.last_search_kind = form.kind;
        let kind_key = match form.kind {
            SearchKind::Users => "users",
            SearchKind::Groups => "groups",
            _ => "other",
        };
        self.start_results(
            format!("{} — {}", form.kind.label(), desc),
            ResultsKind::Search { description: filter.clone() },
            kind_key,
            Request::Search { base, scope, filter, attrs: vec![] },
        );
        Ok(())
    }

    fn remember_search(&mut self, kind: SearchKind, q: &str) {
        let profile = self.profile_name();
        self.search_history.remember(&profile, kind.key(), q);
    }

    pub fn forget_search(&mut self, kind: SearchKind, q: &str) {
        let profile = self.profile_name();
        self.search_history.forget(&profile, kind.key(), q);
    }

    // -----------------------------------------------------------------------------------------
    // Saved searches

    /// The profile's saved searches followed by the shared ones; the flag marks shared entries.
    pub fn saved_searches(&self) -> Vec<(SavedSearch, bool)> {
        let mut out: Vec<(SavedSearch, bool)> = self
            .profile
            .as_ref()
            .and_then(|p| self.config.profile(&p.name))
            .map(|p| p.search.saved.iter().cloned().map(|s| (s, false)).collect())
            .unwrap_or_default();
        out.extend(self.config.search.saved.iter().cloned().map(|s| (s, true)));
        out
    }

    fn saved_list_mut(&mut self, index: usize) -> Option<(&mut Vec<SavedSearch>, usize)> {
        let name = self.profile_name();
        let n = self.config.profile(&name).map(|p| p.search.saved.len()).unwrap_or(0);
        if index < n {
            Some((&mut self.config.profile_mut(&name)?.search.saved, index))
        } else {
            Some((&mut self.config.search.saved, index - n))
        }
    }

    /// Runs a saved search that needs no text.
    pub fn run_saved(&mut self, s: &SavedSearch) -> Result<(), String> {
        filter::validate(&s.filter).map_err(|e| e.to_string())?;
        let base = s.base.clone().filter(|b| !b.trim().is_empty()).unwrap_or_else(|| self.default_search_base());
        let scope = SCOPES[s.scope_index()].0;
        info!(filter = %s.filter, %base, "saved search");
        self.last_search_kind = SearchKind::Saved;
        self.start_results(
            s.name.clone(),
            ResultsKind::Search { description: s.filter.clone() },
            "other",
            Request::Search { base, scope, filter: s.filter.clone(), attrs: vec![] },
        );
        Ok(())
    }

    /// Builds a saved search from what the dialog currently holds.
    pub fn saved_from_form(&self, form: &SearchForm, name: &str) -> Result<SavedSearch, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("enter a name for the saved search".into());
        }
        let q = form.query.text().trim().to_string();
        let profile = self.profile.as_ref().ok_or("not connected")?;
        let filter = match (&form.template, form.kind) {
            (Some((_, t)), _) => t.clone(),
            (None, SearchKind::Raw) => {
                if q.is_empty() {
                    return Err("enter a filter first".into());
                }
                filter::validate(&q.replace("{q}", "x")).map_err(|e| e.to_string())?;
                q
            }
            (None, SearchKind::Attribute) => filter::attribute_filter(&q).map_err(|e| e.to_string())?,
            (None, SearchKind::Users) if !q.is_empty() => flavor::user_filter(profile, self.flavor(), &q),
            (None, SearchKind::Groups) if !q.is_empty() => flavor::group_filter(profile, self.flavor(), &q),
            (None, SearchKind::Users | SearchKind::Groups) => {
                return Err("enter something to search for first".into());
            }
            (None, SearchKind::Dn) => return Err("DN lookups can't be saved — use the Raw filter tab".into()),
            (None, SearchKind::Saved) => return Err("this is already a saved search".into()),
        };
        let base = form.base.text().trim().to_string();
        Ok(SavedSearch {
            name: name.to_string(),
            filter,
            base: (!base.is_empty()).then_some(base),
            scope: match form.scope {
                1 => Some("onelevel".into()),
                2 => Some("base".into()),
                _ => None,
            },
        })
    }

    pub fn add_saved(&mut self, s: SavedSearch, shared: bool) -> Result<(), String> {
        let name = self.profile_name();
        let list = if shared {
            &mut self.config.search.saved
        } else {
            &mut self.config.profile_mut(&name).ok_or("not connected")?.search.saved
        };
        list.retain(|x| !x.name.eq_ignore_ascii_case(&s.name));
        let what = format!("saved \"{}\" for {}", s.name, if shared { "all profiles" } else { "this profile" });
        list.push(s);
        self.persist_config(&what)
    }

    pub fn remove_saved(&mut self, index: usize) -> Result<(), String> {
        let Some((list, i)) = self.saved_list_mut(index) else { return Err("not connected".into()) };
        if i >= list.len() {
            return Ok(());
        }
        let removed = list.remove(i);
        self.persist_config(&format!("deleted saved search \"{}\"", removed.name))
    }

    pub fn rename_saved(&mut self, index: usize, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("enter a name".into());
        }
        let Some((list, i)) = self.saved_list_mut(index) else { return Err("not connected".into()) };
        let Some(s) = list.get_mut(i) else { return Ok(()) };
        s.name = name.to_string();
        self.persist_config(&format!("renamed to \"{name}\""))
    }

    /// Writes config.json; on failure the change stays in memory and the error is returned.
    fn persist_config(&mut self, what: &str) -> Result<(), String> {
        match self.config.persist() {
            Ok(()) => {
                self.set_message(what.to_string(), Level::Info);
                Ok(())
            }
            Err(e) => {
                let msg = format!("{what} (this session only): {e:#}");
                self.set_message(msg.clone(), Level::Error);
                Err(msg)
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Bookmarks

    /// The profile's bookmarks, sorted by name.
    pub fn bookmarks(&self) -> Vec<Bookmark> {
        let mut v = self
            .profile
            .as_ref()
            .and_then(|p| self.config.profile(&p.name))
            .map(|p| p.bookmarks.clone())
            .unwrap_or_default();
        v.sort_by_key(|b| b.name.to_lowercase());
        v
    }

    pub fn is_bookmarked(&self, dn: &str) -> bool {
        self.profile
            .as_ref()
            .and_then(|p| self.config.profile(&p.name))
            .is_some_and(|p| p.bookmarks.iter().any(|b| model::dn_eq(&b.dn, dn)))
    }

    /// `B`: removes the bookmark on the current DN, or asks for a name to add one.
    pub fn toggle_bookmark(&mut self) {
        let Some(dn) = self.current_dn() else {
            self.set_message("nothing selected to bookmark", Level::Info);
            return;
        };
        if self.is_bookmarked(&dn) {
            self.remove_bookmark(&dn);
        } else {
            let name = model::rdn_value(&dn);
            self.overlay = Some(Overlay::BookmarkAdd { dn, input: TextInput::new(&name) });
        }
    }

    pub fn add_bookmark(&mut self, name: &str, dn: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("enter a name for the bookmark".into());
        }
        let pname = self.profile_name();
        let p = self.config.profile_mut(&pname).ok_or("not connected")?;
        p.bookmarks.retain(|b| !model::dn_eq(&b.dn, dn));
        p.bookmarks.push(Bookmark { name: name.to_string(), dn: dn.to_string() });
        self.persist_config(&format!("bookmarked \"{name}\""))
    }

    pub fn remove_bookmark(&mut self, dn: &str) {
        let pname = self.profile_name();
        let Some(p) = self.config.profile_mut(&pname) else { return };
        let before = p.bookmarks.len();
        p.bookmarks.retain(|b| !model::dn_eq(&b.dn, dn));
        if p.bookmarks.len() != before {
            let _ = self.persist_config("bookmark removed");
        }
    }

    pub fn rename_bookmark(&mut self, dn: &str, name: &str) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("enter a name".into());
        }
        let pname = self.profile_name();
        let p = self.config.profile_mut(&pname).ok_or("not connected")?;
        if let Some(b) = p.bookmarks.iter_mut().find(|b| model::dn_eq(&b.dn, dn)) {
            b.name = name.to_string();
        }
        self.persist_config(&format!("renamed to \"{name}\""))
    }

    pub fn show_members(&mut self) {
        let Some(e) = &self.entry.entry else {
            self.set_message("no entry selected", Level::Info);
            return;
        };
        let dn = e.dn.clone();
        if e.kind() != EntryKind::Group
            && e.get("member").is_none()
            && e.get("uniqueMember").is_none()
            && e.get("memberUid").is_none()
        {
            self.set_message("this entry is not a group", Level::Warn);
            return;
        }
        self.show_members_dn(dn);
    }

    pub fn show_members_dn(&mut self, dn: String) {
        self.start_results(
            format!("Members of {}", model::rdn_value(&dn)),
            ResultsKind::Members { dn: dn.clone() },
            "other",
            Request::Members { dn, attrs: vec![] },
        );
    }

    pub fn show_member_of(&mut self, nested: bool) {
        let Some(dn) = self.entry.entry.as_ref().map(|e| e.dn.clone()) else {
            self.set_message("no entry selected", Level::Info);
            return;
        };
        self.show_member_of_dn(dn, nested);
    }

    pub fn show_member_of_dn(&mut self, dn: String, nested: bool) {
        let nested = nested && self.flavor().supports_nested_groups();
        self.start_results(
            format!("{} of {}", if nested { "All groups (nested)" } else { "Groups" }, model::rdn_value(&dn)),
            ResultsKind::MemberOf { dn: dn.clone(), nested },
            "groups",
            Request::MemberOf { dn, nested, attrs: vec![] },
        );
    }

    // -----------------------------------------------------------------------------------------
    // Navigation

    /// Shows an entry, records it in history, and reveals it in the tree.
    pub fn navigate(&mut self, dn: &str) {
        self.sync_history();
        self.history.visit(dn);
        self.show_and_reveal(dn);
    }

    /// Records the entry currently on screen (reached via the tree or results) so Back returns to it.
    fn sync_history(&mut self) {
        if let Some(d) = self.entry.dn.clone() {
            self.history.visit(&d);
        }
    }

    fn show_and_reveal(&mut self, dn: &str) {
        self.request_entry(dn);
        self.reveal = Some(dn.to_string());
        self.advance_reveal();
    }

    pub fn back(&mut self) {
        self.sync_history();
        match self.history.go_back() {
            Some(dn) => self.show_and_reveal(&dn),
            None => self.set_message("no earlier entry in history", Level::Info),
        }
    }

    pub fn forward(&mut self) {
        match self.history.go_forward() {
            Some(dn) => self.show_and_reveal(&dn),
            None => self.set_message("no later entry in history", Level::Info),
        }
    }

    /// Expands the tree down to the reveal target, loading parents as needed.
    fn advance_reveal(&mut self) {
        let Some(target) = self.reveal.clone() else { return };
        let Some(root) = self.tree.root_for(&target) else {
            self.reveal = None;
            return;
        };
        let root_dn = self.tree.get(&root).expect("root").dn.clone();
        let chain = model::ancestors_from(&target, &root_dn).unwrap_or_default();
        let mut parent: Option<Key> = None;
        for anc in chain {
            let k = match &parent {
                None => root.clone(),
                Some(p) => self.tree.ensure_child(p, &anc),
            };
            let node = self.tree.get_mut(&k).expect("node exists");
            node.expanded = true;
            match node.load {
                Load::NotLoaded | Load::Failed(_) => {
                    self.load_children(&k);
                    return;
                }
                Load::Loading(_) => return,
                Load::Loaded => {}
            }
            parent = Some(k);
        }
        let k = match &parent {
            None => root,
            Some(p) => self.tree.ensure_child(p, &target),
        };
        self.tree.select_key(&k);
        self.reveal = None;
    }

    pub fn follow_selected(&mut self) {
        if let Some(dn) = self.entry.selected_dn() {
            self.navigate(&dn);
        } else {
            self.set_message("the selected value is not a DN", Level::Info);
        }
    }

    pub fn open_value_viewer(&mut self) {
        let Some((name, v)) = self.entry.selected_value() else { return };
        let mut lines = Vec::new();
        match v {
            Value::Text(s) => {
                lines.extend(s.lines().map(str::to_string));
                if let Some(a) = decode::annotate(name, v) {
                    lines.push(String::new());
                    lines.push(format!("Decoded: {a}"));
                }
            }
            Value::Binary(b) => {
                if let Some(a) = decode::annotate(name, v) {
                    lines.push(format!("Decoded: {a}"));
                    lines.push(String::new());
                }
                lines.push(format!("{} bytes:", b.len()));
                lines.extend(decode::hexdump(b));
            }
        }
        self.overlay = Some(Overlay::Value { title: name.to_string(), lines, scroll: 0 });
    }

    pub fn copy(&mut self, text: String, what: &str) {
        self.clipboard = Some(text);
        self.set_message(format!("copied {what} to clipboard (OSC 52)"), Level::Info);
    }

    // -----------------------------------------------------------------------------------------
    // Export

    /// `e`: opens the export dialog for whatever is in focus.
    pub fn open_export(&mut self) {
        let what = match (self.focus, &self.results) {
            (Focus::Right, _) => match &self.entry.entry {
                Some(e) => {
                    let mut e = e.clone();
                    if !self.entry.show_operational {
                        e.attrs.retain(|a| !a.operational);
                    }
                    export::What::Entry(Box::new(e))
                }
                None => {
                    self.set_message("no entry to export", Level::Info);
                    return;
                }
            },
            (Focus::Left, Some(r)) => match &r.tree {
                Some(t) => {
                    let rows = t
                        .rows()
                        .into_iter()
                        .filter_map(|row| match row {
                            membertree::Row::Node { key, depth, cycle, .. } => {
                                t.get(&key).map(|n| (depth, n.hit.clone(), cycle))
                            }
                            membertree::Row::Status { .. } => None,
                        })
                        .collect();
                    export::What::Tree { title: r.title.clone(), rows }
                }
                None => export::What::Results {
                    title: r.title.clone(),
                    columns: r.columns.clone(),
                    hits: r.order.iter().filter_map(|&i| r.list.hits.get(i)).cloned().collect(),
                },
            },
            (Focus::Left, None) => {
                let key = match self.tree.selected.clone() {
                    Some(tree::RowId::Node(k)) | Some(tree::RowId::More(k)) | Some(tree::RowId::Status(k)) => k,
                    None => {
                        self.set_message("nothing selected", Level::Info);
                        return;
                    }
                };
                let Some(n) = self.tree.get(&key) else { return };
                let children: Vec<(String, EntryKind)> = n
                    .children
                    .iter()
                    .filter_map(|c| self.tree.get(c))
                    .map(|c| (c.referral.clone().unwrap_or_else(|| c.dn.clone()), c.kind))
                    .collect();
                if children.is_empty() {
                    self.set_message("this node has no loaded children to export (expand it first)", Level::Info);
                    return;
                }
                export::What::Children { dn: n.dn.clone(), children }
            }
        };
        let dir = self
            .profile
            .as_ref()
            .and_then(|p| p.export.dir.clone())
            .map(|d| export::expand_home(&d))
            .or_else(|| directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let format = what.formats()[0];
        let path = dir.join(what.default_name(format)).to_string_lossy().into_owned();
        self.overlay = Some(Overlay::Export(Box::new(ExportForm {
            what,
            format: 0,
            path: TextInput::new(&path),
            decoded: true,
            field: 1,
            error: None,
            note: None,
            confirm: false,
        })));
    }

    /// Enter in the export dialog. Returns `Ok(true)` when the file was written.
    pub fn run_export(&mut self, form: &mut ExportForm) -> Result<bool, String> {
        let typed = form.path.text().trim().to_string();
        if typed.is_empty() {
            return Err("enter a file path".into());
        }
        let path = export::expand_home(&typed);
        if path.is_dir() {
            return Err("that is a directory — add a file name".into());
        }
        if path.exists() && !form.confirm {
            form.confirm = true;
            return Err("file exists — Enter again to overwrite".into());
        }
        let text = export::render(&form.what, form.format(), form.decoded);
        std::fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        let n = form.what.row_count();
        info!(path = %path.display(), rows = n, format = form.format().label(), "exported");
        self.set_message(
            format!("wrote {n} {} to {}", if n == 1 { "row" } else { "rows" }, path.display()),
            Level::Info,
        );
        Ok(true)
    }

    // -----------------------------------------------------------------------------------------
    // Compare

    /// `d`: marks the entry on screen for comparison, or clears the mark if it is already marked.
    pub fn toggle_compare(&mut self) {
        let Some(e) = self.entry.entry.clone() else {
            self.set_message("no entry to mark", Level::Info);
            return;
        };
        if self.compare.as_ref().is_some_and(|c| model::dn_eq(&c.dn, &e.dn)) {
            self.compare = None;
            self.set_message("comparison mark cleared", Level::Info);
        } else {
            self.set_message(
                format!("marked {} — open another entry and press D", model::rdn_value(&e.dn)),
                Level::Info,
            );
            self.compare = Some(e);
        }
    }

    /// `D`: opens the diff of the marked entry against the entry on screen.
    pub fn open_diff(&mut self) {
        let Some(left) = self.compare.clone() else {
            self.set_message("nothing marked — press d on an entry first", Level::Info);
            return;
        };
        let Some(right) = self.entry.entry.clone() else {
            self.set_message("no entry on screen to compare with", Level::Info);
            return;
        };
        if model::dn_eq(&left.dn, &right.dn) {
            self.set_message("this is the marked entry — open a different one to compare", Level::Info);
            return;
        }
        let mut view = diff::DiffView::new(left, right, self.flavor());
        view.show_operational = self.entry.show_operational;
        view.filter = self.entry.filter.clone().unwrap_or_default();
        self.overlay = Some(Overlay::Diff(Box::new(view)));
    }

    /// `r` in the diff view: re-reads both entries.
    pub fn refresh_diff(&mut self) {
        let Some(Overlay::Diff(d)) = &self.overlay else { return };
        let (l, r) = (d.left.dn.clone(), d.right.dn.clone());
        let id = self.worker.send(Request::Entry { dn: l });
        self.pending.insert(id, Pending::Compare);
        if self.entry.dn.as_deref().is_some_and(|dn| model::dn_eq(dn, &r)) {
            self.request_entry(&r);
        } else {
            let id = self.worker.send(Request::Entry { dn: r });
            self.pending.insert(id, Pending::Compare);
        }
        self.set_message("refreshing both entries…", Level::Info);
    }

    /// The DN most relevant to the current focus (entry shown, or selected tree node / result).
    pub fn current_dn(&self) -> Option<String> {
        match self.focus {
            Focus::Right => self.entry.dn.clone(),
            Focus::Left => match &self.results {
                Some(r) => match &r.tree {
                    Some(t) => t.selected_node().map(|n| n.hit.dn.clone()).filter(|d| !d.is_empty()),
                    None => r.selected_hit().map(|h| h.dn.clone()).filter(|d| !d.is_empty()),
                },
                None => self.tree.selected_node().filter(|n| n.referral.is_none()).map(|n| n.dn.clone()),
            },
        }
        .or_else(|| self.entry.dn.clone())
    }

    /// Default base for a new search: the selected container, else the base DN.
    pub fn default_search_base(&self) -> String {
        let base = self.conn.as_ref().map(|c| c.base_dn.clone()).unwrap_or_default();
        if self.results.is_some() {
            return base;
        }
        match self.tree.selected_node() {
            Some(n) if n.referral.is_none() && n.kind.likely_container() => n.dn.clone(),
            _ => base,
        }
    }

    // -----------------------------------------------------------------------------------------
    // Event loop hooks

    /// Called every loop iteration: drains worker replies and fires debounced requests.
    pub fn on_tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        while let Some(reply) = self.worker.try_recv() {
            self.on_reply(reply);
        }
        if let Some((dn, at)) = self.entry.want.clone()
            && at.elapsed() >= ENTRY_DEBOUNCE
        {
            self.request_entry(&dn);
        }
        if let Some(m) = &self.message
            && m.level == Level::Info
            && m.at.elapsed() > Duration::from_secs(6)
        {
            self.message = None;
        }
    }

    pub fn is_busy(&self) -> bool {
        !self.pending.is_empty() || matches!(self.screen, Screen::Connecting { .. })
    }

    fn on_reply(&mut self, reply: Reply) {
        // Connection replies are matched against the connecting screen, not `pending`.
        if let Screen::Connecting { request, .. } = &self.screen
            && *request == reply.id
        {
            let Screen::Connecting { profile, attempt, .. } = std::mem::replace(&mut self.screen, Screen::Browse)
            else {
                unreachable!()
            };
            match reply.response {
                Response::Connected(info) => self.on_connected(*profile, info),
                Response::Failed(f) => self.on_connect_failed(*profile, attempt, f),
                _ => {}
            }
            return;
        }
        let Some(p) = self.pending.remove(&reply.id) else { return };
        if let Response::Failed(f) = &reply.response
            && f.kind == ErrorKind::Disconnected
        {
            self.disconnected = true;
        }
        match (p, reply.response) {
            (Pending::Children { key, started }, Response::Children(list)) => {
                let n = list.children.len();
                let more = list.truncated;
                self.tree.set_children(&key, list);
                self.set_message(
                    format!("{n}{} children in {} ms", if more { "+" } else { "" }, started.elapsed().as_millis()),
                    Level::Info,
                );
                self.advance_reveal();
            }
            (Pending::Children { key, .. }, Response::Failed(f)) => {
                if let Some(n) = self.tree.get_mut(&key) {
                    n.load = Load::Failed(f.title.clone());
                }
                self.set_message(f.to_string(), Level::Error);
                self.reveal = None;
            }
            (Pending::Entry, Response::Entry(e)) => {
                if self.entry.loading == Some(reply.id) {
                    self.entry.loading = None;
                    // Refine the tree icon now that we know the objectClass.
                    if let Some(n) = self.tree.get_mut(&key_of(&e.dn)) {
                        n.kind = e.kind();
                    }
                    if self.entry.state.selected().is_none() {
                        self.entry.state.select(Some(0));
                    }
                    if let Some(Overlay::Diff(d)) = self.overlay.as_mut()
                        && model::dn_eq(&d.right.dn, &e.dn)
                    {
                        d.set_right(*e.clone());
                    }
                    self.entry.entry = Some(*e);
                    let len = self.entry.rows().len();
                    if self.entry.state.selected().is_some_and(|s| s >= len) {
                        self.entry.state.select(Some(len.saturating_sub(1)));
                    }
                }
            }
            (Pending::Entry, Response::Failed(f)) => {
                if self.entry.loading == Some(reply.id) {
                    self.entry.loading = None;
                    self.entry.entry = None;
                    self.set_message(f.to_string(), Level::Error);
                    self.entry.error = Some(f);
                }
            }
            (Pending::Results, Response::Hits(list)) => {
                if let Some(r) = self.results.as_mut().filter(|r| r.loading == Some(reply.id)) {
                    r.loading = None;
                    let n = list.hits.len();
                    let ms = r.started.elapsed().as_millis();
                    r.list = list;
                    r.resort();
                    r.state.select((n > 0).then_some(0));
                    let first = r.hit_at(0).map(|h| h.dn.clone()).filter(|d| !d.is_empty());
                    let trunc = r.list.truncated;
                    self.set_message(
                        format!(
                            "{n} result{}{} in {ms} ms",
                            if n == 1 { "" } else { "s" },
                            if trunc { " (truncated)" } else { "" }
                        ),
                        if trunc { Level::Warn } else { Level::Info },
                    );
                    if let Some(dn) = first {
                        self.want_entry(&dn);
                    }
                }
            }
            (Pending::Compare, Response::Entry(e)) => {
                if let Some(Overlay::Diff(d)) = self.overlay.as_mut() {
                    if model::dn_eq(&d.left.dn, &e.dn) {
                        d.set_left(*e.clone());
                    } else if model::dn_eq(&d.right.dn, &e.dn) {
                        d.set_right(*e.clone());
                    }
                }
                if self.compare.as_ref().is_some_and(|c| model::dn_eq(&c.dn, &e.dn)) {
                    self.compare = Some(*e);
                }
            }
            (Pending::Compare, Response::Failed(f)) => self.set_message(f.to_string(), Level::Error),
            (Pending::TreeNode { key }, Response::Hits(list)) => {
                if let Some(t) = self.results.as_mut().and_then(|r| r.tree.as_mut())
                    && t.get(&key).is_some_and(|n| n.load == membertree::Load::Loading(reply.id))
                {
                    let n = list.hits.len();
                    t.set_children(&key, list.hits);
                    self.set_message(format!("{n} loaded"), Level::Info);
                }
            }
            (Pending::TreeNode { key }, Response::Failed(f)) => {
                if let Some(t) = self.results.as_mut().and_then(|r| r.tree.as_mut()) {
                    t.set_failed(&key, f.title.clone());
                }
                self.set_message(f.to_string(), Level::Error);
            }
            (Pending::Results, Response::Failed(f)) => {
                if let Some(r) = self.results.as_mut().filter(|r| r.loading == Some(reply.id)) {
                    r.loading = None;
                    r.list.warning = Some(f.title.clone());
                }
                self.show_error(f);
            }
            _ => {}
        }
    }

    fn on_connect_failed(&mut self, profile: Profile, attempt: u32, f: Failure) {
        let reconnecting = self.conn.is_some() && self.profile.as_ref().is_some_and(|p| p.name == profile.name);
        if f.kind == ErrorKind::InvalidCredentials
            && let Some(Creds::Simple { bind_dn, .. }) = self.creds.clone()
        {
            if attempt >= MAX_LOGIN_ATTEMPTS {
                self.back_to_picker();
                let msg =
                    format!("{} — stopped after {MAX_LOGIN_ATTEMPTS} attempts to avoid locking the account", f.title);
                self.show_error(Failure { title: msg, ..f });
                return;
            }
            // Keep the DN; let the user edit it only if it didn't come from secrets.json.
            let dn_from_user = matches!(self.secrets.resolve(&profile), Resolution::NeedBoth);
            let error = format!("{} (attempt {} of {MAX_LOGIN_ATTEMPTS})", f.title, attempt + 1);
            self.show_login(profile, Some(bind_dn), attempt + 1, Some(error));
            if let Screen::Login(form) = &mut self.screen {
                form.dn_editable = dn_from_user;
                form.field = 1;
            }
            return;
        }
        if reconnecting {
            self.screen = Screen::Browse;
            self.disconnected = true;
            self.show_error(f);
            return;
        }
        self.back_to_picker();
        self.show_error(f);
    }

    pub fn handle_event(&mut self, ev: ratatui::crossterm::event::Event) {
        keys::handle_event(self, ev);
    }
}
