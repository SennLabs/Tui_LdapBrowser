//! Mouse support (plan section 5.6.6): hit-testing against the areas recorded during the last
//! draw. No widget keeps its own geometry; the renderer fills [`HitAreas`] every frame.

use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::widgets::ListState;

use super::{App, Focus, Level, Overlay};

const DOUBLE_CLICK: Duration = Duration::from_millis(400);
const WHEEL_ROWS: usize = 3;

/// Screen areas recorded by the renderer. All coordinates are absolute.
#[derive(Debug, Default, Clone)]
pub struct HitAreas {
    /// Whole left pane (tree or results), including its border.
    pub left_pane: Option<Rect>,
    /// Rows of the left pane's list or table (excluding any header), with the first visible index.
    pub left_rows: Option<Rect>,
    pub left_offset: usize,
    /// Results header row and the x-ranges of its columns: index 0 is the name column.
    pub left_header: Option<Rect>,
    pub left_columns: Vec<(u16, u16)>,
    /// Whole entry pane and its attribute rows.
    pub right_pane: Option<Rect>,
    pub right_rows: Option<Rect>,
    pub right_offset: usize,
    /// Footer hints: the area of each key label and the key it stands for.
    pub footer: Vec<(Rect, String)>,
    /// A popup's area, so clicks outside it can be told apart.
    pub popup: Option<Rect>,
    /// Clickable tabs inside a popup (search type, export format): area and index.
    pub tabs: Vec<(Rect, usize)>,
    /// Rows of a list inside a popup (columns, bookmarks, saved searches, menu) and its offset.
    pub popup_rows: Option<Rect>,
    pub popup_offset: usize,
}

/// A right-click menu. Each item re-dispatches a key the user could have pressed.
pub struct Menu {
    pub items: Vec<(&'static str, KeyEvent)>,
    pub state: ListState,
    pub at: (u16, u16),
}

fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn code(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn inside(r: Option<Rect>, x: u16, y: u16) -> bool {
    r.is_some_and(|r| x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height)
}

/// Row index under `y` for a list drawn in `rows` starting at `offset`.
fn row_at(rows: Option<Rect>, offset: usize, y: u16) -> Option<usize> {
    let r = rows?;
    (y >= r.y && y < r.y + r.height).then(|| offset + (y - r.y) as usize)
}

pub fn handle_mouse(app: &mut App, m: MouseEvent) {
    let (x, y) = (m.column, m.row);
    match m.kind {
        MouseEventKind::ScrollDown => scroll(app, x, y, WHEEL_ROWS as isize),
        MouseEventKind::ScrollUp => scroll(app, x, y, -(WHEEL_ROWS as isize)),
        MouseEventKind::Down(MouseButton::Left) => {
            let double = app.last_click.is_some_and(|(at, lx, ly)| at.elapsed() < DOUBLE_CLICK && lx == x && ly == y);
            app.last_click = Some((Instant::now(), x, y));
            click(app, x, y, double);
        }
        MouseEventKind::Down(MouseButton::Right) => right_click(app, x, y),
        _ => {}
    }
}

fn scroll(app: &mut App, x: u16, y: u16, delta: isize) {
    let hit = app.hit.clone();
    if app.overlay.is_some() {
        // Popups scroll their own content; a wheel outside a popup is ignored.
        let code = if delta > 0 { KeyCode::Down } else { KeyCode::Up };
        for _ in 0..delta.unsigned_abs() {
            super::keys::handle_event(
                app,
                ratatui::crossterm::event::Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
            );
        }
        return;
    }
    let pane = if inside(hit.right_pane, x, y) {
        Focus::Right
    } else if inside(hit.left_pane, x, y) {
        Focus::Left
    } else {
        app.focus
    };
    let code = if delta > 0 { KeyCode::Down } else { KeyCode::Up };
    let saved = app.focus;
    app.focus = pane;
    for _ in 0..delta.unsigned_abs() {
        super::keys::browse_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }
    app.focus = saved;
}

fn click(app: &mut App, x: u16, y: u16, double: bool) {
    let hit = app.hit.clone();
    if let Some(ov) = &app.overlay {
        popup_click(app, ov_kind(ov), &hit, x, y, double);
        return;
    }
    if !matches!(app.screen, super::Screen::Browse) {
        return;
    }
    // Footer hints act like their key.
    if let Some((_, k)) = hit.footer.iter().find(|(r, _)| inside(Some(*r), x, y)) {
        if let Some(ev) = hint_key(k) {
            super::keys::browse_key(app, ev);
        }
        return;
    }
    // Results header: sort by that column.
    if inside(hit.left_header, x, y)
        && let Some(r) = app.results.as_mut()
        && r.tree.is_none()
    {
        if let Some(i) = hit.left_columns.iter().position(|(a, b)| x >= *a && x < *b) {
            r.sort_by_column(if i == 0 { None } else { Some(i - 1) });
            let label = r.sort_label();
            app.set_message(format!("sorted by {label}"), Level::Info);
        }
        return;
    }
    if inside(hit.left_pane, x, y) {
        app.focus = Focus::Left;
        if let Some(i) = row_at(hit.left_rows, hit.left_offset, y) {
            left_row_click(app, i, x, double);
        }
        return;
    }
    if inside(hit.right_pane, x, y) {
        app.focus = Focus::Right;
        if let Some(i) = row_at(hit.right_rows, hit.right_offset, y)
            && i < app.entry.rows().len()
        {
            app.entry.state.select(Some(i));
            if double {
                super::keys::browse_key(app, code(KeyCode::Enter));
            }
        }
    }
}

/// Which pane-specific behaviour a click on left-pane row `i` triggers.
fn left_row_click(app: &mut App, i: usize, x: u16, double: bool) {
    if let Some(r) = app.results.as_mut() {
        if let Some(t) = r.tree.as_mut() {
            let rows = t.rows();
            if i >= rows.len() {
                return;
            }
            t.selected = i;
            let arrow_hit = match &rows[i] {
                super::membertree::Row::Node { depth, .. } => {
                    let ax = app.hit.left_rows.map(|r| r.x).unwrap_or(0) + (*depth as u16) * 2;
                    x >= ax && x < ax + 2
                }
                _ => false,
            };
            if arrow_hit || double {
                super::keys::browse_key(app, code(KeyCode::Enter));
            } else if let Some(dn) = t.selected_node().map(|n| n.hit.dn.clone()).filter(|d| !d.is_empty()) {
                app.want_entry(&dn);
            }
            return;
        }
        if i >= r.order.len() {
            return;
        }
        r.state.select(Some(i));
        if double {
            super::keys::browse_key(app, code(KeyCode::Enter));
        } else if let Some(dn) = r.selected_hit().map(|h| h.dn.clone()).filter(|d| !d.is_empty()) {
            app.want_entry(&dn);
        }
        return;
    }
    let rows = app.tree.rows();
    if i >= rows.len() {
        return;
    }
    let arrow_hit = match &rows[i] {
        super::tree::Row::Node { depth, .. } => {
            let ax = app.hit.left_rows.map(|r| r.x).unwrap_or(0) + (*depth as u16) * 2;
            x >= ax && x < ax + 2
        }
        _ => false,
    };
    if arrow_hit && !double {
        // Expand or collapse without moving the selection or changing the entry pane.
        if let super::tree::Row::Node { key, .. } = &rows[i]
            && let Some(n) = app.tree.get_mut(key)
            && n.referral.is_none()
        {
            if n.expanded {
                n.expanded = false;
            } else {
                n.expanded = true;
                let needs_load = matches!(n.load, super::tree::Load::NotLoaded | super::tree::Load::Failed(_));
                if needs_load {
                    let key = key.clone();
                    app.load_children(&key);
                }
            }
        }
        return;
    }
    app.tree.select_index(&rows, i);
    if double {
        super::keys::browse_key(app, code(KeyCode::Enter));
    } else if let Some(n) = app.tree.selected_node().filter(|n| n.referral.is_none()) {
        let dn = n.dn.clone();
        app.want_entry(&dn);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OvKind {
    Search,
    Export,
    ListLike,
    Menu,
    Other,
}

fn ov_kind(ov: &Overlay) -> OvKind {
    match ov {
        Overlay::Search(_) => OvKind::Search,
        Overlay::Export(_) => OvKind::Export,
        Overlay::Columns { .. } | Overlay::Bookmarks { .. } => OvKind::ListLike,
        Overlay::Menu(_) => OvKind::Menu,
        _ => OvKind::Other,
    }
}

fn popup_click(app: &mut App, kind: OvKind, hit: &HitAreas, x: u16, y: u16, double: bool) {
    if let Some((_, i)) = hit.tabs.iter().find(|(r, _)| inside(Some(*r), x, y)) {
        match app.overlay.as_mut() {
            Some(Overlay::Search(f)) => {
                f.kind = super::SearchKind::ALL[*i % super::SearchKind::ALL.len()];
                f.template = None;
                f.recall = None;
                if f.field >= f.field_count() {
                    f.field = 1;
                }
            }
            Some(Overlay::Export(f)) => f.set_format(*i),
            _ => {}
        }
        return;
    }
    if kind == OvKind::Menu && !inside(hit.popup, x, y) {
        app.overlay = None;
        return;
    }
    let Some(i) = row_at(hit.popup_rows, hit.popup_offset, y) else { return };
    let bookmarks = app.bookmarks().len();
    let saved = app.saved_searches().len();
    let mut press_enter = false;
    match app.overlay.as_mut() {
        Some(Overlay::Columns { items, state, .. }) if i < items.len() => {
            state.select(Some(i));
            items[i].1 = !items[i].1;
        }
        Some(Overlay::Bookmarks { state, .. }) if i < bookmarks => {
            state.select(Some(i));
            press_enter = double;
        }
        Some(Overlay::Search(f)) if f.showing_saved_list() && i < saved => {
            f.saved_sel = i;
            f.field = 1;
            press_enter = double;
        }
        Some(Overlay::Menu(m)) if i < m.items.len() => {
            m.state.select(Some(i));
            press_enter = true;
        }
        _ => {}
    }
    if press_enter {
        super::keys::handle_event(app, ratatui::crossterm::event::Event::Key(code(KeyCode::Enter)));
    }
}

/// Maps a footer hint label to the key it stands for.
fn hint_key(label: &str) -> Option<KeyEvent> {
    let first = label.split('/').next().unwrap_or(label);
    Some(match first {
        "↑↓" | "Ctrl-←→" => return None,
        "Enter" => code(KeyCode::Enter),
        "Esc" => code(KeyCode::Esc),
        "Tab" => code(KeyCode::Tab),
        "→" => code(KeyCode::Right),
        "←" => code(KeyCode::Left),
        s if s.chars().count() == 1 => key(s.chars().next()?),
        _ => return None,
    })
}

fn right_click(app: &mut App, x: u16, y: u16) {
    if app.overlay.is_some() || !matches!(app.screen, super::Screen::Browse) {
        return;
    }
    let hit = app.hit.clone();
    let items: Vec<(&'static str, KeyEvent)> = if inside(hit.right_pane, x, y) {
        app.focus = Focus::Right;
        if let Some(i) = row_at(hit.right_rows, hit.right_offset, y)
            && i < app.entry.rows().len()
        {
            app.entry.state.select(Some(i));
        }
        vec![
            ("Follow DN", key('f')),
            ("View value", key('v')),
            ("Copy value", key('Y')),
            ("Copy entry DN", key('y')),
            ("Filter attributes", key(':')),
            ("Mark for compare", key('d')),
            ("Diff with marked", key('D')),
            ("Members", key('m')),
            ("Groups", key('M')),
            ("Bookmark", key('B')),
            ("Export entry", key('e')),
        ]
    } else if inside(hit.left_pane, x, y) {
        app.focus = Focus::Left;
        if let Some(i) = row_at(hit.left_rows, hit.left_offset, y) {
            // Select without expanding or navigating.
            if let Some(r) = app.results.as_mut() {
                match r.tree.as_mut() {
                    Some(t) if i < t.rows().len() => t.selected = i,
                    None if i < r.order.len() => r.state.select(Some(i)),
                    _ => {}
                }
            } else {
                let rows = app.tree.rows();
                if i < rows.len() {
                    app.tree.select_index(&rows, i);
                }
            }
        }
        if app.results.is_some() {
            vec![
                ("Open", code(KeyCode::Enter)),
                ("Copy DN", key('y')),
                ("Members", key('m')),
                ("Groups", key('M')),
                ("Bookmark", key('B')),
                ("Sort", key('s')),
                ("Columns", key('c')),
                ("Tree / flat", key('t')),
                ("Export list", key('e')),
                ("Close results", code(KeyCode::Esc)),
            ]
        } else {
            vec![
                ("Expand / collapse", code(KeyCode::Enter)),
                ("Copy DN", key('y')),
                ("Filter children", key(':')),
                ("Refresh", key('r')),
                ("Members", key('m')),
                ("Groups", key('M')),
                ("Bookmark", key('B')),
                ("Mark for compare", key('d')),
                ("Export children", key('e')),
            ]
        }
    } else {
        return;
    };
    let mut state = ListState::default();
    state.select(Some(0));
    app.overlay = Some(Overlay::Menu(Box::new(Menu { items, state, at: (x, y) })));
}
