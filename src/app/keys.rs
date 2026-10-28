//! Keyboard and paste handling for every screen and overlay.

use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::diff::{DiffRow, DiffView};
use super::history::SearchHistory;
use super::input::TextInput;
use super::tree::{Load, Row};
use super::{App, Focus, Level, Overlay, Recall, ResultsKind, SCOPES, Screen, SearchForm, SearchKind, SubPrompt};
use crate::config::SavedSearch;
use crate::ldap::model;

const PAGE: usize = 10;

pub fn handle_event(app: &mut App, ev: Event) {
    match ev {
        Event::Key(k) if k.kind != KeyEventKind::Release => handle_key(app, k),
        Event::Paste(text) => handle_paste(app, &text),
        Event::Mouse(m) => super::mouse::handle_mouse(app, m),
        _ => {}
    }
}

fn handle_paste(app: &mut App, text: &str) {
    if let Some(input) = active_input(app) {
        input.insert_str(text);
    }
    apply_live_filter(app);
}

/// Pushes the text of an inline filter input into the view it filters.
fn apply_live_filter(app: &mut App) {
    match app.overlay.as_mut() {
        Some(Overlay::AttrFilter { input }) => {
            let text = input.text().to_string();
            app.entry.set_filter(&text);
        }
        Some(Overlay::Diff(d)) => {
            if let Some(text) = d.editing.as_ref().map(|i| i.text().to_string()) {
                d.set_filter(&text);
            }
        }
        _ => {}
    }
}

fn active_input(app: &mut App) -> Option<&mut TextInput> {
    match &mut app.overlay {
        Some(Overlay::Goto { input, .. })
        | Some(Overlay::Filter { input, .. })
        | Some(Overlay::AttrFilter { input }) => return Some(input),
        Some(Overlay::Diff(d)) => return d.editing.as_mut(),
        Some(Overlay::BookmarkAdd { input, .. }) => return Some(input),
        Some(Overlay::Bookmarks { rename, .. }) => return rename.as_mut(),
        Some(Overlay::Columns { adding, .. }) => return adding.as_mut(),
        Some(Overlay::Export(f)) if f.field == 1 => return Some(&mut f.path),
        Some(Overlay::Search(f)) => {
            let list = f.showing_saved_list();
            return match (&mut f.sub, f.field, list) {
                (Some(SubPrompt::Save { name, .. } | SubPrompt::Rename { name, .. }), _, _) => Some(name),
                (None, 1, false) => Some(&mut f.query),
                (None, 2, false) => Some(&mut f.base),
                _ => None,
            };
        }
        _ => {}
    }
    match &mut app.screen {
        Screen::Login(f) => Some(if f.field == 0 && f.dn_editable { &mut f.dn } else { &mut f.password }),
        _ => None,
    }
}

fn is_ctrl_c(k: &KeyEvent) -> bool {
    k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL)
}

fn handle_key(app: &mut App, k: KeyEvent) {
    if is_ctrl_c(&k) {
        app.should_quit = true;
        return;
    }
    if app.overlay.is_some() {
        overlay_key(app, k);
        return;
    }
    match &mut app.screen {
        Screen::Picker { .. } => picker_key(app, k),
        Screen::Login(_) => login_key(app, k),
        Screen::Connecting { .. } => {
            if matches!(k.code, KeyCode::Esc | KeyCode::Char('q')) {
                app.back_to_picker();
            }
        }
        Screen::Browse => browse_key(app, k),
    }
}

fn picker_key(app: &mut App, k: KeyEvent) {
    let names = app.config.profile_names();
    let Screen::Picker { state } = &mut app.screen else { return };
    let i = state.selected().unwrap_or(0);
    match k.code {
        KeyCode::Up | KeyCode::Char('k') => state.select(Some(i.saturating_sub(1))),
        KeyCode::Down | KeyCode::Char('j') => state.select(Some((i + 1).min(names.len().saturating_sub(1)))),
        KeyCode::Home | KeyCode::Char('g') => state.select(Some(0)),
        KeyCode::End | KeyCode::Char('G') => state.select(Some(names.len().saturating_sub(1))),
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            if let Some(n) = names.get(i).cloned() {
                app.start_profile(&n);
            }
        }
        KeyCode::Char('?') => app.overlay = Some(Overlay::Help { scroll: 0 }),
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        _ => {}
    }
}

fn login_key(app: &mut App, k: KeyEvent) {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Esc => {
            app.back_to_picker();
            return;
        }
        KeyCode::Enter => {
            if let Screen::Login(f) = &mut app.screen
                && f.field == 0
                && f.password.text().is_empty()
            {
                f.field = 1;
                return;
            }
            app.submit_login(false);
            return;
        }
        KeyCode::Char('n') if ctrl => {
            app.submit_login(true);
            return;
        }
        _ => {}
    }
    let Screen::Login(f) = &mut app.screen else { return };
    match k.code {
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down if f.dn_editable => {
            f.field = 1 - f.field;
        }
        _ => {
            let input = if f.field == 0 && f.dn_editable { &mut f.dn } else { &mut f.password };
            input.handle_key(k);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Overlays

fn overlay_key(app: &mut App, k: KeyEvent) {
    let Some(ov) = app.overlay.as_mut() else { return };
    match ov {
        Overlay::Help { scroll } | Overlay::Error { scroll, .. } | Overlay::Value { scroll, .. } => match k.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter | KeyCode::Char('?') => app.overlay = None,
            KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => *scroll = scroll.saturating_add(PAGE as u16),
            KeyCode::PageUp => *scroll = scroll.saturating_sub(PAGE as u16),
            KeyCode::Home => *scroll = 0,
            KeyCode::Char('y') => {
                let text = match app.overlay.as_ref() {
                    Some(Overlay::Value { lines, .. }) => Some(lines.join("\n")),
                    Some(Overlay::Error { failure, .. }) => Some(format!("{}\n{}", failure.title, failure.detail)),
                    _ => None,
                };
                if let Some(t) = text {
                    app.copy(t, "text");
                }
            }
            _ => {}
        },
        Overlay::Goto { input, error } => match k.code {
            KeyCode::Esc => app.overlay = None,
            KeyCode::Enter => {
                let dn = input.text().trim().to_string();
                if !model::looks_like_dn(&dn) {
                    *error = Some("not a valid DN (expected attr=value,attr=value…)".into());
                    return;
                }
                app.overlay = None;
                app.navigate(&dn);
            }
            _ => {
                input.handle_key(k);
                *error = None;
            }
        },
        Overlay::Filter { key, input } => match k.code {
            KeyCode::Esc => app.overlay = None,
            KeyCode::Enter => {
                let key = key.clone();
                let p = input.text().trim().to_string();
                app.overlay = None;
                let limit = app.tree.child_limit;
                if let Some(n) = app.tree.get_mut(&key) {
                    n.prefix = (!p.is_empty()).then_some(p);
                    n.limit = limit;
                    n.expanded = true;
                }
                app.load_children(&key);
            }
            _ => {
                input.handle_key(k);
            }
        },
        Overlay::AttrFilter { input } => match k.code {
            KeyCode::Esc => {
                app.entry.set_filter("");
                app.overlay = None;
            }
            KeyCode::Enter | KeyCode::Tab => {
                app.overlay = None;
                app.focus = Focus::Right;
            }
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown => {
                // Move in the entry pane while the filter stays open.
                let len = app.entry.rows().len();
                let cur = app.entry.state.selected().unwrap_or(0);
                if let Some(n) = move_index(cur, len, &k) {
                    app.entry.state.select(Some(n));
                }
            }
            _ => {
                input.handle_key(k);
                apply_live_filter(app);
            }
        },
        Overlay::Diff(_) => diff_key(app, k),
        Overlay::Search(_) => search_key(app, k),
        Overlay::BookmarkAdd { dn, input } => match k.code {
            KeyCode::Esc => app.overlay = None,
            KeyCode::Enter => {
                let (dn, name) = (dn.clone(), input.text().to_string());
                app.overlay = None;
                if let Err(e) = app.add_bookmark(&name, &dn) {
                    app.set_message(e, Level::Warn);
                }
            }
            _ => {
                input.handle_key(k);
            }
        },
        Overlay::Bookmarks { .. } => bookmarks_key(app, k),
        Overlay::Columns { .. } => columns_key(app, k),
        Overlay::Export(_) => export_key(app, k),
        Overlay::Menu(m) => {
            let len = m.items.len();
            let cur = m.state.selected().unwrap_or(0);
            if let Some(n) = move_index(cur, len, &k) {
                m.state.select(Some(n));
                return;
            }
            match k.code {
                KeyCode::Esc | KeyCode::Char('q') => app.overlay = None,
                KeyCode::Enter => {
                    let ev = m.items.get(cur).map(|(_, ev)| *ev);
                    app.overlay = None;
                    if let Some(ev) = ev {
                        browse_key(app, ev);
                    }
                }
                _ => {}
            }
        }
    }
}

fn export_key(app: &mut App, k: KeyEvent) {
    let Some(Overlay::Export(f)) = app.overlay.as_mut() else { return };
    match k.code {
        KeyCode::Esc => app.overlay = None,
        KeyCode::Enter => {
            let Some(Overlay::Export(mut form)) = app.overlay.take() else { return };
            match app.run_export(&mut form) {
                Ok(_) => {}
                Err(e) => {
                    form.error = Some(e);
                    app.overlay = Some(Overlay::Export(form));
                }
            }
        }
        KeyCode::Down => f.field = (f.field + 1) % 3,
        KeyCode::Up | KeyCode::BackTab => f.field = (f.field + 2) % 3,
        KeyCode::Tab if f.field != 1 => f.field = (f.field + 1) % 3,
        KeyCode::Tab => {
            let (done, note) = super::export::complete_path(f.path.text());
            f.path.set(&done);
            f.note = note;
            f.confirm = false;
        }
        _ => match f.field {
            0 => match k.code {
                KeyCode::Left | KeyCode::Char('h') => f.set_format(f.format + f.what.formats().len() - 1),
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') => f.set_format(f.format + 1),
                _ => {}
            },
            2 => {
                if matches!(k.code, KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right | KeyCode::Char('x')) {
                    f.decoded = !f.decoded;
                }
            }
            _ => {
                if f.path.handle_key(k) {
                    f.confirm = false;
                    f.error = None;
                    f.note = None;
                }
            }
        },
    }
}

fn columns_key(app: &mut App, k: KeyEvent) {
    let Some(Overlay::Columns { items, state, adding }) = app.overlay.as_mut() else { return };
    let cur = state.selected().unwrap_or(0).min(items.len().saturating_sub(1));
    if let Some(input) = adding.as_mut() {
        match k.code {
            KeyCode::Esc => *adding = None,
            KeyCode::Enter => {
                let name = input.text().trim().to_string();
                *adding = None;
                if name.is_empty() {
                    return;
                }
                if !crate::ldap::filter::valid_attribute(&name) && !super::columns::is_virtual(&name) {
                    app.set_message(format!("\"{name}\" is not an attribute name"), Level::Warn);
                    return;
                }
                match items.iter().position(|(x, _)| x.eq_ignore_ascii_case(&name)) {
                    Some(i) => {
                        items[i].1 = true;
                        state.select(Some(i));
                    }
                    None => {
                        let at = items.iter().filter(|(_, on)| *on).count();
                        items.insert(at, (name, true));
                        state.select(Some(at));
                    }
                }
            }
            _ => {
                input.handle_key(k);
            }
        }
        return;
    }
    if let Some(n) = move_index(cur, items.len(), &k)
        && !matches!(k.code, KeyCode::Char('G'))
    {
        state.select(Some(n));
        return;
    }
    match k.code {
        KeyCode::Esc | KeyCode::Char('q') => app.overlay = None,
        KeyCode::Char(' ') | KeyCode::Char('x') => {
            if let Some(it) = items.get_mut(cur) {
                it.1 = !it.1;
            }
        }
        KeyCode::Char('J') if cur + 1 < items.len() => {
            items.swap(cur, cur + 1);
            state.select(Some(cur + 1));
        }
        KeyCode::Char('K') if cur > 0 => {
            items.swap(cur, cur - 1);
            state.select(Some(cur - 1));
        }
        KeyCode::Char('a') | KeyCode::Char('/') => *adding = Some(TextInput::default()),
        KeyCode::Enter => {
            let cols: Vec<String> = items.iter().filter(|(_, on)| *on).map(|(c, _)| c.clone()).collect();
            app.overlay = None;
            app.apply_columns(cols);
        }
        _ => {}
    }
}

fn bookmarks_key(app: &mut App, k: KeyEvent) {
    let list = app.bookmarks();
    let Some(Overlay::Bookmarks { state, rename }) = app.overlay.as_mut() else { return };
    let cur = state.selected().unwrap_or(0).min(list.len().saturating_sub(1));
    if let Some(input) = rename.as_mut() {
        match k.code {
            KeyCode::Esc => *rename = None,
            KeyCode::Enter => {
                let name = input.text().to_string();
                *rename = None;
                if let Some(b) = list.get(cur)
                    && let Err(e) = app.rename_bookmark(&b.dn, &name)
                {
                    app.set_message(e, Level::Warn);
                }
            }
            _ => {
                input.handle_key(k);
            }
        }
        return;
    }
    if let Some(n) = move_index(cur, list.len(), &k) {
        state.select(Some(n));
        return;
    }
    match k.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('\'') => app.overlay = None,
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('f') => {
            if let Some(b) = list.get(cur) {
                let dn = b.dn.clone();
                app.overlay = None;
                app.navigate(&dn);
                app.focus = Focus::Right;
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(b) = list.get(cur) {
                let dn = b.dn.clone();
                app.remove_bookmark(&dn);
                let n = app.bookmarks().len();
                if let Some(Overlay::Bookmarks { state, .. }) = app.overlay.as_mut() {
                    state.select((n > 0).then_some(cur.min(n - 1)));
                }
            }
        }
        KeyCode::Char('e') | KeyCode::Char('r') => {
            if let Some(b) = list.get(cur) {
                *rename = Some(TextInput::new(&b.name));
            }
        }
        KeyCode::Char('y') => {
            if let Some(b) = list.get(cur) {
                let dn = b.dn.clone();
                app.copy(dn, "DN");
            }
        }
        _ => {}
    }
}

fn diff_key(app: &mut App, k: KeyEvent) {
    let Some(Overlay::Diff(d)) = app.overlay.as_mut() else { return };
    // Inline attribute filter takes every key while it is open.
    if let Some(input) = d.editing.as_mut() {
        match k.code {
            KeyCode::Esc => {
                d.editing = None;
                d.set_filter("");
            }
            KeyCode::Enter | KeyCode::Tab => d.editing = None,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown => diff_move(d, &k),
            _ => {
                input.handle_key(k);
                apply_live_filter(app);
            }
        }
        return;
    }
    diff_move(d, &k);
    match k.code {
        KeyCode::Esc | KeyCode::Char('q') => app.overlay = None,
        KeyCode::Char('a') => {
            d.only_differences = !d.only_differences;
            d.clamp();
        }
        KeyCode::Char('o') => {
            d.show_operational = !d.show_operational;
            d.clamp();
        }
        KeyCode::Char('i') => d.toggle_identity(),
        KeyCode::Enter if matches!(d.selected_row(), Some(DiffRow::IdentityHeader(_))) => d.toggle_identity(),
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l') => {
            d.side = 1 - d.side;
        }
        KeyCode::Char(':') => d.editing = Some(TextInput::new(&d.filter)),
        KeyCode::Char('r') => app.refresh_diff(),
        KeyCode::Char('y') => {
            let dn = d.side_dn().to_string();
            app.copy(dn, "DN");
        }
        KeyCode::Char('Y') => {
            if let Some((_, v)) = d.selected_value() {
                let text = match v {
                    model::Value::Text(s) => s.clone(),
                    model::Value::Binary(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
                };
                app.copy(text, "value");
            }
        }
        KeyCode::Enter | KeyCode::Char('f') => {
            if let Some(dn) = d.selected_dn() {
                app.overlay = None;
                app.navigate(&dn);
                app.focus = Focus::Right;
            } else {
                app.set_message("the selected value is not a DN", Level::Info);
            }
        }
        _ => {}
    }
}

fn diff_move(d: &mut DiffView, k: &KeyEvent) {
    let len = d.rows().len();
    let cur = d.state.selected().unwrap_or(0);
    if let Some(n) = move_index(cur, len, k) {
        d.state.select(Some(n));
    }
}

/// What a key in the search dialog asks the app to do once the form borrow is released.
enum SearchAction {
    None,
    Close,
    Run,
    RunSaved(usize),
    EditSaved(usize),
    DeleteSaved(usize),
    RenameSaved(usize, String),
    Save(String, bool),
    Forget(SearchKind, String),
}

fn search_key(app: &mut App, k: KeyEvent) {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let profile = app.profile.as_ref().map(|p| p.name.clone()).unwrap_or_default();
    let saved = app.saved_searches();
    let Some(Overlay::Search(f)) = app.overlay.as_mut() else { return };
    let mut action = SearchAction::None;

    if let Some(sub) = f.sub.as_mut() {
        // Save / rename prompt: takes every key.
        match k.code {
            KeyCode::Esc => f.sub = None,
            KeyCode::Enter => match f.sub.take() {
                Some(SubPrompt::Save { name, shared }) => {
                    action = SearchAction::Save(name.text().trim().to_string(), shared);
                }
                Some(SubPrompt::Rename { index, name }) => {
                    action = SearchAction::RenameSaved(index, name.text().trim().to_string());
                }
                None => {}
            },
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                if let SubPrompt::Save { shared, .. } = sub {
                    *shared = !*shared;
                }
            }
            _ => {
                let (SubPrompt::Save { name, .. } | SubPrompt::Rename { name, .. }) = sub;
                name.handle_key(k);
            }
        }
    } else {
        match k.code {
            KeyCode::Esc => action = SearchAction::Close,
            KeyCode::Char('s') if ctrl => {
                if f.showing_saved_list() {
                    f.error = Some("switch to another tab to save a new search".into());
                } else {
                    let default = match &f.template {
                        Some((name, _)) => name.clone(),
                        None => f.query.text().trim().to_string(),
                    };
                    f.sub = Some(SubPrompt::Save { name: TextInput::new(&default), shared: false });
                }
            }
            KeyCode::Enter => {
                action = if f.showing_saved_list() { SearchAction::RunSaved(f.saved_sel) } else { SearchAction::Run };
            }
            KeyCode::Tab => f.field = (f.field + 1) % f.field_count(),
            KeyCode::BackTab => f.field = (f.field + f.field_count() - 1) % f.field_count(),
            _ => {
                f.error = None;
                // Ctrl+←/→ switches search type from any field.
                if ctrl && matches!(k.code, KeyCode::Left | KeyCode::Right) {
                    cycle_kind(f, k.code == KeyCode::Right);
                } else {
                    action = search_field_key(&app.search_history, &profile, f, k, &saved);
                }
            }
        }
    }

    match action {
        SearchAction::None => {}
        SearchAction::Close => app.overlay = None,
        SearchAction::Run => {
            let Some(Overlay::Search(form)) = app.overlay.take() else { return };
            if let Err(e) = app.run_search(&form) {
                let mut form = form;
                form.error = Some(e);
                app.overlay = Some(Overlay::Search(form));
            }
        }
        SearchAction::RunSaved(i) => {
            let Some((s, _)) = saved.get(i) else {
                if let Some(Overlay::Search(f)) = app.overlay.as_mut() {
                    f.error = Some("no saved searches yet — Ctrl-S in another tab saves one".into());
                }
                return;
            };
            if s.takes_text() {
                let base = s.base.clone().unwrap_or_else(|| app.default_search_base());
                if let Some(Overlay::Search(f)) = app.overlay.as_mut() {
                    f.template = Some((s.name.clone(), s.filter.clone()));
                    f.query.clear();
                    f.base.set(&base);
                    f.scope = s.scope_index();
                    f.field = 1;
                    f.recall = None;
                }
                return;
            }
            let s = s.clone();
            let Some(Overlay::Search(form)) = app.overlay.take() else { return };
            if let Err(e) = app.run_saved(&s) {
                let mut form = form;
                form.error = Some(e);
                app.overlay = Some(Overlay::Search(form));
            }
        }
        SearchAction::EditSaved(i) => {
            let Some((s, _)) = saved.get(i) else { return };
            let base = s.base.clone().unwrap_or_else(|| app.default_search_base());
            if let Some(Overlay::Search(f)) = app.overlay.as_mut() {
                f.kind = SearchKind::Raw;
                f.template = None;
                f.query.set(&s.filter);
                f.base.set(&base);
                f.scope = s.scope_index();
                f.field = 1;
                f.recall = None;
            }
        }
        SearchAction::DeleteSaved(i) => {
            let result = app.remove_saved(i);
            let n = app.saved_searches().len();
            if let Some(Overlay::Search(f)) = app.overlay.as_mut() {
                f.saved_sel = f.saved_sel.min(n.saturating_sub(1));
                f.error = result.err();
            }
        }
        SearchAction::RenameSaved(i, name) => {
            let result = app.rename_saved(i, &name);
            if let Some(Overlay::Search(f)) = app.overlay.as_mut() {
                f.error = result.err();
            }
        }
        SearchAction::Save(name, shared) => {
            let Some(Overlay::Search(form)) = app.overlay.take() else { return };
            let result = app.saved_from_form(&form, &name).and_then(|s| app.add_saved(s, shared));
            let mut form = form;
            form.error = result.err();
            app.overlay = Some(Overlay::Search(form));
        }
        SearchAction::Forget(kind, text) => app.forget_search(kind, &text),
    }
}

/// Keys for the focused field (type tabs, query / saved list, base, scope).
fn search_field_key(
    history: &SearchHistory,
    profile: &str,
    f: &mut SearchForm,
    k: KeyEvent,
    saved: &[(SavedSearch, bool)],
) -> SearchAction {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match f.field {
        0 => match k.code {
            KeyCode::Left | KeyCode::Char('h') => cycle_kind(f, false),
            KeyCode::Right | KeyCode::Char('l') => cycle_kind(f, true),
            KeyCode::Down => f.field = 1,
            _ => {}
        },
        1 if f.showing_saved_list() => match k.code {
            KeyCode::Up | KeyCode::Char('k') => f.saved_sel = f.saved_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => f.saved_sel = (f.saved_sel + 1).min(saved.len().saturating_sub(1)),
            KeyCode::Home => f.saved_sel = 0,
            KeyCode::End => f.saved_sel = saved.len().saturating_sub(1),
            KeyCode::Char('e') if !saved.is_empty() => return SearchAction::EditSaved(f.saved_sel),
            KeyCode::Char('d') | KeyCode::Delete if !saved.is_empty() => return SearchAction::DeleteSaved(f.saved_sel),
            KeyCode::Char('r') if !saved.is_empty() => {
                let name = saved[f.saved_sel].0.name.clone();
                f.sub = Some(SubPrompt::Rename { index: f.saved_sel, name: TextInput::new(&name) });
            }
            _ => {}
        },
        1 => {
            let kind = if f.template.is_some() { SearchKind::Saved } else { f.kind };
            match k.code {
                KeyCode::Up => match f.recall.as_mut() {
                    Some(r) => {
                        if r.pos + 1 < r.items.len() {
                            r.pos += 1;
                            f.query.set(&r.items[r.pos].clone());
                        }
                    }
                    None => {
                        let items = history.matching(profile, kind.key(), f.query.text());
                        if let Some(first) = items.first() {
                            let typed = f.query.text().to_string();
                            f.query.set(first);
                            f.recall = Some(Recall { items, pos: 0, typed });
                        }
                    }
                },
                KeyCode::Down => match f.recall.as_mut() {
                    Some(r) if r.pos > 0 => {
                        r.pos -= 1;
                        f.query.set(&r.items[r.pos].clone());
                    }
                    Some(r) => {
                        f.query.set(&r.typed.clone());
                        f.recall = None;
                    }
                    None => f.field = 2,
                },
                KeyCode::Char('d') if ctrl => {
                    if let Some(r) = f.recall.as_mut() {
                        let gone = r.items.remove(r.pos);
                        if r.items.is_empty() {
                            f.query.set(&r.typed.clone());
                            f.recall = None;
                        } else {
                            r.pos = r.pos.min(r.items.len() - 1);
                            f.query.set(&r.items[r.pos].clone());
                        }
                        return SearchAction::Forget(kind, gone);
                    }
                }
                KeyCode::Esc => {}
                _ => {
                    if f.query.handle_key(k) {
                        f.recall = None;
                    }
                }
            }
        }
        2 => match k.code {
            KeyCode::Up => f.field = 1,
            KeyCode::Down => f.field = 3,
            _ => {
                f.base.handle_key(k);
            }
        },
        _ => match k.code {
            KeyCode::Left | KeyCode::Char('h') => f.scope = (f.scope + SCOPES.len() - 1) % SCOPES.len(),
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') => f.scope = (f.scope + 1) % SCOPES.len(),
            KeyCode::Up => f.field = 2,
            _ => {}
        },
    }
    SearchAction::None
}

fn cycle_kind(f: &mut SearchForm, forward: bool) {
    let n = SearchKind::ALL.len();
    let i = SearchKind::ALL.iter().position(|k| *k == f.kind).unwrap_or(0);
    f.kind = SearchKind::ALL[if forward { (i + 1) % n } else { (i + n - 1) % n }];
    f.template = None;
    f.recall = None;
    if f.field >= f.field_count() {
        f.field = 1;
    }
}

pub fn open_search(app: &mut App) {
    let base = app.default_search_base();
    app.overlay = Some(Overlay::Search(Box::new(SearchForm {
        kind: app.last_search_kind,
        query: TextInput::default(),
        base: TextInput::new(&base),
        scope: 0,
        field: 1,
        error: None,
        recall: None,
        saved_sel: 0,
        template: None,
        sub: None,
    })));
}

// ---------------------------------------------------------------------------------------------
// Browse screen

pub(super) fn browse_key(app: &mut App, k: KeyEvent) {
    // Global keys first.
    match k.code {
        KeyCode::Char('q') => {
            app.should_quit = true;
            return;
        }
        KeyCode::Char('?') => {
            app.overlay = Some(Overlay::Help { scroll: 0 });
            return;
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.focus = if app.focus == Focus::Left { Focus::Right } else { Focus::Left };
            return;
        }
        KeyCode::Char('/') => {
            open_search(app);
            return;
        }
        KeyCode::Char('g') => {
            let dn = app.current_dn().unwrap_or_default();
            app.overlay = Some(Overlay::Goto { input: TextInput::new(&dn), error: None });
            return;
        }
        KeyCode::Char('b') | KeyCode::Backspace => {
            app.back();
            return;
        }
        KeyCode::Char('F') => {
            app.forward();
            return;
        }
        KeyCode::Char('m') => {
            app.show_members();
            return;
        }
        KeyCode::Char('M') => {
            app.show_member_of(false);
            return;
        }
        KeyCode::Char('d') => {
            app.toggle_compare();
            return;
        }
        KeyCode::Char('B') => {
            app.toggle_bookmark();
            return;
        }
        KeyCode::Char('e') => {
            app.open_export();
            return;
        }
        KeyCode::Char('\'') => {
            let mut state = ratatui::widgets::ListState::default();
            state.select((!app.bookmarks().is_empty()).then_some(0));
            app.overlay = Some(Overlay::Bookmarks { state, rename: None });
            return;
        }
        KeyCode::Char('D') => {
            app.open_diff();
            return;
        }
        KeyCode::Char('o') => {
            app.entry.show_operational = !app.entry.show_operational;
            app.entry.state.select(Some(0));
            app.set_message(
                if app.entry.show_operational {
                    "showing operational attributes"
                } else {
                    "hiding operational attributes"
                },
                Level::Info,
            );
            return;
        }
        KeyCode::Char('y') => {
            if let Some(dn) = app.current_dn() {
                app.copy(dn, "DN");
            }
            return;
        }
        KeyCode::Char('R') => {
            app.reconnect();
            return;
        }
        KeyCode::Char('P') => {
            app.back_to_picker();
            return;
        }
        _ => {}
    }
    match app.focus {
        Focus::Left if app.results.is_some() => results_key(app, k),
        Focus::Left => tree_key(app, k),
        Focus::Right => entry_key(app, k),
    }
}

fn move_index(cur: usize, len: usize, k: &KeyEvent) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let last = len - 1;
    Some(match k.code {
        KeyCode::Up | KeyCode::Char('k') => cur.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => (cur + 1).min(last),
        KeyCode::PageUp => cur.saturating_sub(PAGE),
        KeyCode::PageDown => (cur + PAGE).min(last),
        KeyCode::Home => 0,
        KeyCode::End | KeyCode::Char('G') => last,
        _ => return None,
    })
}

fn tree_key(app: &mut App, k: KeyEvent) {
    let rows = app.tree.rows();
    let idx = app.tree.selected_index(&rows);
    if let Some(n) = move_index(idx, rows.len(), &k) {
        app.tree.select_index(&rows, n);
        on_tree_selection(app);
        return;
    }
    let Some(row) = rows.get(idx).cloned() else { return };
    match (k.code, row) {
        (KeyCode::Enter | KeyCode::Right | KeyCode::Char('l'), Row::More { parent, .. }) => {
            let step = app.tree.child_limit;
            if let Some(n) = app.tree.get_mut(&parent) {
                n.limit += step;
            }
            app.load_children(&parent);
        }
        (KeyCode::Enter | KeyCode::Right | KeyCode::Char('l'), Row::Node { key, .. }) => {
            let Some(n) = app.tree.get(&key) else { return };
            if n.referral.is_some() {
                app.set_message("referrals to other servers are not followed", Level::Info);
                return;
            }
            if n.expanded {
                // Move to the first child.
                if k.code != KeyCode::Enter && idx + 1 < rows.len() {
                    app.tree.select_index(&rows, idx + 1);
                    on_tree_selection(app);
                } else if k.code == KeyCode::Enter {
                    app.tree.get_mut(&key).expect("node").expanded = false;
                }
                return;
            }
            let needs_load = matches!(n.load, Load::NotLoaded | Load::Failed(_));
            app.tree.get_mut(&key).expect("node").expanded = true;
            if needs_load {
                app.load_children(&key);
            }
        }
        (KeyCode::Left | KeyCode::Char('h'), row) => {
            let key = match row {
                Row::Node { key, .. } => key,
                Row::More { parent, .. } | Row::Status { parent, .. } => {
                    app.tree.select_key(&parent);
                    on_tree_selection(app);
                    return;
                }
            };
            if let Some(n) = app.tree.get_mut(&key)
                && n.expanded
            {
                n.expanded = false;
                return;
            }
            if let Some(p) = app.tree.parent_of(&key) {
                app.tree.select_key(&p);
                on_tree_selection(app);
            }
        }
        (KeyCode::Char('r'), row) => {
            let key = match row {
                Row::Node { key, .. } => key,
                Row::More { parent, .. } | Row::Status { parent, .. } => parent,
            };
            if let Some(n) = app.tree.get_mut(&key)
                && n.referral.is_none()
            {
                n.expanded = true;
                let dn = n.dn.clone();
                app.load_children(&key);
                app.request_entry(&dn);
            }
        }
        (KeyCode::Char(':'), row) => {
            let key = match row {
                Row::Node { key, .. } => key,
                Row::More { parent, .. } | Row::Status { parent, .. } => parent,
            };
            let current = app.tree.get(&key).and_then(|n| n.prefix.clone()).unwrap_or_default();
            app.overlay = Some(Overlay::Filter { key, input: TextInput::new(&current) });
        }
        (KeyCode::Char('f'), _) => {
            app.set_message("select a DN value in the entry pane (Tab) to follow it", Level::Info)
        }
        (KeyCode::Esc, _) => {
            app.cancel_current();
        }
        _ => {}
    }
}

fn on_tree_selection(app: &mut App) {
    if let Some(n) = app.tree.selected_node() {
        if n.referral.is_some() {
            return;
        }
        let dn = n.dn.clone();
        app.want_entry(&dn);
    }
}

fn results_key(app: &mut App, k: KeyEvent) {
    if app.results.as_ref().is_some_and(|r| r.tree.is_some()) {
        member_tree_key(app, k);
        return;
    }
    let Some(r) = app.results.as_mut() else { return };
    let len = r.order.len();
    let cur = r.state.selected().unwrap_or(0);
    if let Some(n) = move_index(cur, len, &k) {
        r.state.select(Some(n));
        if let Some(dn) = r.hit_at(n).map(|h| h.dn.clone()).filter(|d| !d.is_empty()) {
            app.want_entry(&dn);
        }
        return;
    }
    match k.code {
        KeyCode::Esc => {
            if r.loading.is_some() {
                app.cancel_current();
            } else {
                app.results = None;
                if let Some(dn) = app.tree.selected_node().filter(|n| n.referral.is_none()).map(|n| n.dn.clone()) {
                    app.want_entry(&dn);
                }
            }
        }
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('f') => {
            if let Some(dn) = r.selected_hit().map(|h| h.dn.clone()).filter(|d| !d.is_empty()) {
                app.navigate(&dn);
                app.focus = Focus::Right;
            }
        }
        KeyCode::Char('s') => {
            r.cycle_sort();
            let label = r.sort_label();
            app.set_message(format!("sorted by {label}"), Level::Info);
        }
        KeyCode::Char('S') => {
            r.reverse_sort();
            let label = r.sort_label();
            app.set_message(format!("sorted by {label}"), Level::Info);
        }
        KeyCode::Char('c') => app.open_columns(),
        KeyCode::Char('t') => app.toggle_member_tree(),
        KeyCode::Char('n') => {
            if let ResultsKind::MemberOf { dn, nested } = r.kind.clone() {
                if !app.flavor().supports_nested_groups() {
                    app.set_message(format!("{} has no nested groups", app.flavor().label()), Level::Info);
                    return;
                }
                app.show_member_of_dn(dn, !nested);
            }
        }
        KeyCode::Char('r') => {
            let kind = r.kind.clone();
            match kind {
                ResultsKind::Members { dn } => app.show_members_dn(dn),
                ResultsKind::MemberOf { dn, nested } => app.show_member_of_dn(dn, nested),
                ResultsKind::Search { .. } => open_search(app),
            }
        }
        _ => {}
    }
}

fn member_tree_key(app: &mut App, k: KeyEvent) {
    use super::membertree::Row as MRow;
    let Some(r) = app.results.as_mut() else { return };
    let Some(t) = r.tree.as_mut() else { return };
    let rows = t.rows();
    if let Some(n) = move_index(t.selected, rows.len(), &k) {
        t.selected = n;
        if let Some(dn) = t.selected_node().map(|n| n.hit.dn.clone()).filter(|d| !d.is_empty()) {
            app.want_entry(&dn);
        }
        return;
    }
    let row = rows.get(t.selected).cloned();
    match (k.code, row) {
        (KeyCode::Esc, _) => {
            app.results = None;
            if let Some(dn) = app.tree.selected_node().filter(|n| n.referral.is_none()).map(|n| n.dn.clone()) {
                app.want_entry(&dn);
            }
        }
        (KeyCode::Char('t'), _) => app.toggle_member_tree(),
        (KeyCode::Char('n'), _) => {
            app.set_message("the tree always shows nesting; t returns to the flat list", Level::Info)
        }
        (KeyCode::Enter | KeyCode::Right | KeyCode::Char('l'), Some(MRow::Node { key, cycle, at_limit, .. })) => {
            if cycle {
                app.set_message("this group is already on the path above (cycle)", Level::Info);
                return;
            }
            if at_limit {
                app.set_message(format!("depth limit of {} reached", super::membertree::DEPTH_LIMIT), Level::Info);
                return;
            }
            let Some(n) = t.get(&key) else { return };
            if n.expanded && k.code != KeyCode::Enter {
                t.selected = (t.selected + 1).min(rows.len().saturating_sub(1));
            } else if n.expanded {
                t.get_mut(&key).expect("node").expanded = false;
            } else if t.expandable(n) {
                app.expand_tree_node(&key);
            } else {
                app.set_message("not a group", Level::Info);
            }
        }
        (KeyCode::Left | KeyCode::Char('h'), Some(MRow::Node { key, .. })) => {
            if t.get(&key).is_some_and(|n| n.expanded) && key != t.root {
                t.get_mut(&key).expect("node").expanded = false;
            } else if let Some(p) = t.parent_of_selected() {
                t.select_key(&p);
            }
        }
        (KeyCode::Left | KeyCode::Char('h'), Some(MRow::Status { .. })) => {
            if let Some(p) = t.parent_of_selected() {
                t.select_key(&p);
            }
        }
        (KeyCode::Char('f'), Some(MRow::Node { key, .. })) => {
            if let Some(dn) = t.get(&key).map(|n| n.hit.dn.clone()).filter(|d| !d.is_empty()) {
                app.navigate(&dn);
                app.focus = Focus::Right;
            }
        }
        (KeyCode::Char('r'), Some(MRow::Node { key, .. })) => app.reload_tree_node(&key),
        _ => {}
    }
}

fn entry_key(app: &mut App, k: KeyEvent) {
    let len = app.entry.rows().len();
    let cur = app.entry.state.selected().unwrap_or(0);
    if let Some(n) = move_index(cur, len, &k) {
        app.entry.state.select(Some(n));
        return;
    }
    match k.code {
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            if app.entry.selected_dn().is_some() {
                app.follow_selected();
            } else {
                app.open_value_viewer();
            }
        }
        KeyCode::Char('f') => app.follow_selected(),
        KeyCode::Char('v') => app.open_value_viewer(),
        KeyCode::Char('Y') => {
            if let Some((_, v)) = app.entry.selected_value() {
                let text = match v {
                    crate::ldap::model::Value::Text(s) => s.clone(),
                    crate::ldap::model::Value::Binary(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
                };
                app.copy(text, "value");
            }
        }
        KeyCode::Char('r') => {
            if let Some(dn) = app.entry.dn.clone() {
                app.request_entry(&dn);
            }
        }
        KeyCode::Char(':') => {
            let current = app.entry.filter.clone().unwrap_or_default();
            app.overlay = Some(Overlay::AttrFilter { input: TextInput::new(&current) });
        }
        KeyCode::Esc if app.entry.filter.is_some() => {
            app.entry.set_filter("");
            app.set_message("attribute filter cleared", Level::Info);
        }
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Esc => app.focus = Focus::Left,
        _ => {}
    }
}
