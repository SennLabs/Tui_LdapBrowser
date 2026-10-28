//! Main browse screen: status bar, tree or results pane, entry pane, footer.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, List, ListItem, Paragraph, Row as TRow, Table, Wrap};

use super::{Ctx, block, hints_at, kind_letter, truncate};
use crate::app::tree::Row;
use crate::app::{App, Focus, Level, Overlay, columns, is_followable};
use crate::config::Scheme;
use crate::ldap::decode;
use crate::ldap::model::{self, Value};

pub fn draw(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    let [status, main, foot] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)]).areas(area);
    status_bar(f, app, ctx, status);
    let [left, right] = if area.width < super::STACK_WIDTH {
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(main)
    } else {
        Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)]).areas(main)
    };
    if app.results.as_ref().is_some_and(|r| r.tree.is_some()) {
        member_tree_pane(f, app, ctx, left);
    } else if app.results.is_some() {
        results_pane(f, app, ctx, left);
    } else {
        tree_pane(f, app, ctx, left);
    }
    entry_pane(f, app, ctx, right);
    footer(f, app, ctx, foot);
}

fn status_bar(f: &mut Frame, app: &App, ctx: &Ctx, area: Rect) {
    let Some(p) = &app.profile else { return };
    let t = &ctx.theme;
    let sep = Span::styled(format!(" {} ", ctx.sym.sep), t.dim());
    let mut spans = vec![Span::styled(" LdapTui ", t.accent()), sep.clone(), Span::raw(p.name.clone()), sep.clone()];
    spans.push(Span::styled(p.url(), t.dim()));
    spans.push(Span::raw(" "));
    let bound = app.conn.as_ref().and_then(|c| c.bound_as.clone());
    match (p.scheme, p.insecure_skip_verify) {
        (Scheme::Ldaps, false) => spans.push(Span::styled(" TLS ✓ ", t.badge(Level::Info))),
        (Scheme::Ldaps, true) => spans.push(Span::styled(" INSECURE TLS ", t.badge(Level::Error))),
        (Scheme::Ldap, _) if bound.is_some() && area.width >= 130 => {
            spans.push(Span::styled(" PLAIN — password sent unencrypted ", t.badge(Level::Warn)))
        }
        (Scheme::Ldap, _) if bound.is_some() => spans.push(Span::styled(" PLAIN ⚠ ", t.badge(Level::Warn))),
        (Scheme::Ldap, _) => spans.push(Span::styled(" PLAIN ", t.badge(Level::Warn))),
    }
    spans.push(sep.clone());
    spans.push(Span::raw(match &bound {
        Some(b) => format!("bound as {}", short_identity(b)),
        None => "anonymous".to_string(),
    }));
    spans.push(sep.clone());
    spans.push(Span::styled(app.flavor().label(), t.accent()));
    if let Some(c) = &app.compare {
        spans.push(sep.clone());
        spans.push(Span::styled(format!("compare: {}", model::rdn_value(&c.dn)), t.warn()));
    }
    if app.disconnected {
        spans.push(sep.clone());
        spans.push(Span::styled(" DISCONNECTED — R to reconnect ", t.badge(Level::Error)));
    }
    if app.is_busy() {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(ctx.sym.spin(app.tick), t.accent()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn short_identity(dn: &str) -> String {
    if model::looks_like_dn(dn) { model::rdn_value(dn) } else { dn.to_string() }
}

fn tree_pane(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    let focused = app.focus == Focus::Left;
    let rows = app.tree.rows();
    let sel = app.tree.selected_index(&rows);
    let t = &ctx.theme;
    let width = area.width.saturating_sub(4) as usize;
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| match r {
            Row::Node { key, depth } => {
                let n = app.tree.get(key).expect("node");
                let indent = "  ".repeat(*depth);
                let arrow = if n.referral.is_some() {
                    ctx.sym.leaf
                } else if n.expanded {
                    ctx.sym.expanded
                } else if n.expandable() {
                    ctx.sym.collapsed
                } else {
                    ctx.sym.leaf
                };
                let label = if n.referral.is_some() { format!("↪ {}", n.label) } else { n.label.clone() };
                let marked = n.referral.is_none() && app.is_bookmarked(&n.dn);
                let used = indent.chars().count() + 4 + if marked { 2 } else { 0 };
                let mut spans = vec![
                    Span::raw(indent),
                    Span::styled(format!("{arrow} "), t.dim()),
                    Span::styled(kind_letter(n.kind), t.kind(n.kind)),
                    Span::raw(" "),
                    Span::raw(truncate(&label, width.saturating_sub(used), ctx.sym.ellipsis)),
                ];
                if marked {
                    spans.push(Span::styled(format!(" {}", ctx.sym.bookmark), t.warn()));
                }
                if let crate::app::tree::Load::Loading(_) = n.load {
                    spans.push(Span::styled(format!(" {}", ctx.sym.spin(app.tick)), t.accent()));
                }
                ListItem::new(Line::from(spans))
            }
            Row::More { depth, shown, .. } => ListItem::new(Line::from(vec![
                Span::raw("  ".repeat(*depth)),
                Span::styled(format!("{} {shown} shown — Enter to load more", ctx.sym.ellipsis), t.link()),
            ])),
            Row::Status { depth, text, error, .. } => ListItem::new(Line::from(vec![
                Span::raw("  ".repeat(*depth)),
                Span::styled(text.clone(), if *error { t.error() } else { t.dim() }),
            ])),
        })
        .collect();
    app.tree_state.select(Some(sel));
    let b = block(" Directory ", focused, ctx);
    let inner = b.inner(area);
    let list = List::new(items).block(b).highlight_style(t.selected(focused));
    f.render_stateful_widget(list, area, &mut app.tree_state);
    app.hit.left_pane = Some(area);
    app.hit.left_rows = Some(inner);
    app.hit.left_offset = app.tree_state.offset();
}

fn results_pane(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    let focused = app.focus == Focus::Left;
    let t = &ctx.theme;
    let bookmarked: Vec<bool> = app
        .results
        .as_ref()
        .map(|r| r.list.hits.iter().map(|h| app.is_bookmarked(&h.dn)).collect())
        .unwrap_or_default();
    let Some(r) = app.results.as_mut() else { return };
    let mut title = vec![Span::raw(format!(" {} ", r.title))];
    if r.loading.is_some() {
        title.push(Span::styled(format!("{} ", ctx.sym.spin(app.tick)), t.accent()));
    } else {
        title.push(Span::styled(
            format!("({}{}) ", r.list.hits.len(), if r.list.truncated { "+" } else { "" }),
            t.dim(),
        ));
    }
    let b = block(Line::from(title), focused, ctx);
    let inner = b.inner(area);
    f.render_widget(b, area);

    let mut notes: Vec<Line> = Vec::new();
    if r.list.truncated {
        notes.push(Line::from(Span::styled("results truncated at size_limit — narrow the search", t.warn())));
    }
    if let Some(w) = &r.list.warning {
        notes.push(Line::from(Span::styled(w.clone(), t.warn())));
    }
    if !r.list.referrals.is_empty() {
        notes.push(Line::from(Span::styled(
            format!("{} referral(s) not followed: {}", r.list.referrals.len(), r.list.referrals.join(", ")),
            t.dim(),
        )));
    }
    let [note_area, table_area] =
        Layout::vertical([Constraint::Length(notes.len() as u16), Constraint::Min(1)]).areas(inner);
    f.render_widget(Paragraph::new(notes), note_area);

    if r.loading.is_none() && r.list.hits.is_empty() {
        f.render_widget(Paragraph::new(Span::styled("No results.", t.dim())), table_area);
        return;
    }
    // Column layout: kind letter, name, then as many configured columns as fit (dropped from the right).
    let total_w = table_area.width as usize;
    let name_w = r.order.iter().filter_map(|&i| r.list.hits.get(i)).map(|h| h.name.chars().count() + 2).max();
    let name_w = name_w.unwrap_or(10).clamp(12, (total_w / 3).max(12));
    let mut widths: Vec<u16> = vec![1, name_w as u16];
    let mut shown_cols: Vec<(usize, Vec<String>)> = Vec::new();
    let mut used = 1 + 1 + name_w + 1;
    for (ci, col) in r.columns.iter().enumerate() {
        let cells: Vec<String> =
            r.order.iter().filter_map(|&i| r.list.hits.get(i)).map(|h| columns::cell_text(h, col)).collect();
        let w =
            cells.iter().map(|c| c.chars().count()).chain(std::iter::once(col.chars().count() + 2)).max().unwrap_or(6);
        let w = w.clamp(6, 36);
        if used + w + 1 > total_w {
            break;
        }
        used += w + 1;
        widths.push(w as u16);
        shown_cols.push((ci, cells));
    }
    let hidden = r.columns.len() - shown_cols.len();
    let sort_hidden =
        r.sort.0.as_deref().is_some_and(|s| !shown_cols.iter().any(|(ci, _)| r.columns[*ci].eq_ignore_ascii_case(s)));
    let sort_col = r.sort.0.as_deref().map(|s| s.to_ascii_lowercase());
    let arrow = |desc: bool| {
        if desc {
            if ctx.sym.ellipsis == "..." { " v" } else { " ▼" }
        } else if ctx.sym.ellipsis == "..." {
            " ^"
        } else {
            " ▲"
        }
    };
    let mut header = vec![Cell::from(""), {
        let mut name = String::from("name");
        if sort_col.is_none() {
            name.push_str(arrow(r.sort.1));
        }
        Cell::from(Span::styled(name, t.accent()))
    }];
    for (ci, _) in &shown_cols {
        let col = &r.columns[*ci];
        let mut label = col.clone();
        if sort_col.as_deref().is_some_and(|s| s == col.to_ascii_lowercase()) {
            label.push_str(arrow(r.sort.1));
        }
        header.push(Cell::from(Span::styled(label, t.accent())));
    }
    let mut rows: Vec<TRow> = Vec::with_capacity(r.order.len());
    for (ri, &hi) in r.order.iter().enumerate() {
        let Some(h) = r.list.hits.get(hi) else { continue };
        let mut name = vec![Span::raw(truncate(&h.name, name_w, ctx.sym.ellipsis))];
        if bookmarked.get(hi).copied().unwrap_or(false) {
            name.push(Span::styled(format!(" {}", ctx.sym.bookmark), t.warn()));
        }
        if let Some(tag) = &h.tag {
            name.push(Span::styled(format!(" [{tag}]"), t.accent()));
        }
        let mut cells =
            vec![Cell::from(Span::styled(kind_letter(h.kind), t.kind(h.kind))), Cell::from(Line::from(name))];
        for (k, (_, texts)) in shown_cols.iter().enumerate() {
            let w = widths[k + 2] as usize;
            cells.push(Cell::from(Span::styled(truncate(&texts[ri], w, ctx.sym.ellipsis), t.dim())));
        }
        rows.push(TRow::new(cells));
    }
    let constraints: Vec<Constraint> = widths.iter().map(|w| Constraint::Length(*w)).collect();
    let [table_area, note] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(if hidden > 0 { 1 } else { 0 })]).areas(table_area);
    let table = Table::new(rows, constraints)
        .header(TRow::new(header))
        .column_spacing(1)
        .row_highlight_style(t.selected(focused));
    f.render_stateful_widget(table, table_area, &mut r.state);
    let offset = r.state.offset();
    let mut cols = Vec::new();
    let mut x = table_area.x + widths[0] + 1;
    for w in widths.iter().skip(1) {
        cols.push((x, x + w));
        x += w + 1;
    }
    app.hit.left_pane = Some(area);
    app.hit.left_header = Some(Rect::new(table_area.x, table_area.y, table_area.width, 1));
    app.hit.left_columns = cols;
    app.hit.left_rows =
        Some(Rect::new(table_area.x, table_area.y + 1, table_area.width, table_area.height.saturating_sub(1)));
    app.hit.left_offset = offset;
    if hidden > 0 {
        let mut text = format!("{hidden} column{} hidden (narrow) — c to choose", if hidden == 1 { "" } else { "s" });
        if sort_hidden {
            text = format!("sorted by {} · {text}", r.sort_label());
        }
        f.render_widget(Paragraph::new(Span::styled(text, t.dim())), note);
    }
}

fn member_tree_pane(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    use crate::app::membertree::{Direction, Load, Row as MRow};
    let focused = app.focus == Focus::Left;
    let t = &ctx.theme;
    let tick = app.tick;
    let bookmarked = |dn: &str| app.is_bookmarked(dn);
    let Some(r) = app.results.as_ref() else { return };
    let Some(tree) = r.tree.as_ref() else { return };
    let what = match tree.direction {
        Direction::Members => "members",
        Direction::MemberOf => "groups",
    };
    let title =
        Line::from(vec![Span::raw(format!(" {} ", r.title)), Span::styled(format!("· tree of {what} "), t.dim())]);
    let b = block(title, focused, ctx);
    let inner = b.inner(area);
    f.render_widget(b, area);
    let width = inner.width as usize;
    let rows = tree.rows();
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match row {
            MRow::Node { key, depth, cycle, at_limit } => {
                let n = tree.get(key).expect("node");
                let indent = "  ".repeat(*depth);
                let arrow = if *cycle {
                    if ctx.sym.ellipsis == "..." { "@" } else { "↻" }
                } else if *at_limit || !tree.expandable(n) {
                    ctx.sym.leaf
                } else if n.expanded {
                    ctx.sym.expanded
                } else {
                    ctx.sym.collapsed
                };
                let mut spans = vec![
                    Span::raw(indent.clone()),
                    Span::styled(format!("{arrow} "), if *cycle { t.warn() } else { t.dim() }),
                    Span::styled(kind_letter(n.hit.kind), t.kind(n.hit.kind)),
                    Span::raw(" "),
                    Span::raw(n.hit.name.clone()),
                ];
                let mut used = indent.chars().count() + 4 + n.hit.name.chars().count();
                if bookmarked(&n.hit.dn) {
                    spans.push(Span::styled(format!(" {}", ctx.sym.bookmark), t.warn()));
                    used += 2;
                }
                if let Some(tag) = &n.hit.tag {
                    spans.push(Span::styled(format!(" [{tag}]"), t.accent()));
                    used += tag.chars().count() + 3;
                }
                if *cycle {
                    spans.push(Span::styled(" (cycle)", t.warn()));
                    used += 8;
                }
                if let Load::Loading(_) = n.load {
                    spans.push(Span::styled(format!(" {}", ctx.sym.spin(tick)), t.accent()));
                    used += 2;
                }
                let room = width.saturating_sub(used + 2);
                if room > 12 && !n.hit.dn.is_empty() {
                    let parent = model::parent_dn(&n.hit.dn).unwrap_or_default();
                    spans.push(Span::styled(format!("  {}", truncate(&parent, room, ctx.sym.ellipsis)), t.dim()));
                }
                ListItem::new(Line::from(spans))
            }
            MRow::Status { depth, text, error } => ListItem::new(Line::from(vec![
                Span::raw("  ".repeat(*depth)),
                Span::styled(text.clone(), if *error { t.error() } else { t.dim() }),
            ])),
        })
        .collect();
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(tree.selected.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(List::new(items).highlight_style(t.selected(focused)), inner, &mut state);
    app.hit.left_pane = Some(area);
    app.hit.left_rows = Some(inner);
    app.hit.left_offset = state.offset();
}

fn entry_pane(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    let focused = app.focus == Focus::Right;
    let t = &ctx.theme;
    let title_dn = app.entry.dn.clone().unwrap_or_default();
    let mut title = vec![Span::raw(" Entry ")];
    if app.entry.loading.is_some() {
        title.push(Span::styled(format!("{} ", ctx.sym.spin(app.tick)), t.accent()));
    }
    if app.entry.show_operational {
        title.push(Span::styled("+operational ", t.dim()));
    }
    let filter_input = match &app.overlay {
        Some(Overlay::AttrFilter { input }) => Some(input),
        _ => None,
    };
    if let Some(flt) = &app.entry.filter {
        let (n, m) = app.entry.filter_counts();
        title.push(Span::styled(format!("· filter: {flt} ({n} of {m}) "), t.accent()));
    }
    let b = block(Line::from(title), focused || filter_input.is_some(), ctx);
    let inner = b.inner(area);
    f.render_widget(b, area);
    app.hit.right_pane = Some(area);
    let [dn_area, filter_area, table_area] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(if filter_input.is_some() { 1 } else { 0 }),
        Constraint::Min(1),
    ])
    .areas(inner);
    if let Some(input) = filter_input {
        let mut spans = vec![Span::styled("filter: ", t.accent())];
        spans.extend(super::input_line(input, true, filter_area.width.saturating_sub(8) as usize, ctx).spans);
        spans.push(Span::styled("   Enter keep · Esc clear", t.dim()));
        f.render_widget(Paragraph::new(Line::from(spans)), filter_area);
    }
    f.render_widget(Paragraph::new(Line::from(Span::styled(title_dn, t.accent()))).wrap(Wrap { trim: false }), dn_area);

    if let Some(err) = &app.entry.error {
        let mut lines = vec![Line::from(Span::styled(err.title.clone(), t.error()))];
        if let Some(h) = &err.hint {
            lines.push(Line::from(h.clone()));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), table_area);
        return;
    }
    let Some(entry) = &app.entry.entry else {
        let msg = if let Some(n) = app.tree.selected_node().filter(|n| n.referral.is_some() && app.results.is_none()) {
            format!("Referral to {} (not followed)", n.referral.clone().unwrap_or_default())
        } else if app.entry.loading.is_some() || app.entry.want.is_some() {
            "loading…".into()
        } else {
            "Select an entry.".into()
        };
        f.render_widget(Paragraph::new(Span::styled(msg, t.dim())), table_area);
        return;
    };

    let rows_idx = app.entry.rows();
    if rows_idx.is_empty() && app.entry.filter.is_some() {
        f.render_widget(Paragraph::new(Span::styled("No attribute matches the filter.", t.dim())), table_area);
        return;
    }
    let name_w = entry
        .attrs
        .iter()
        .filter(|a| app.entry.show_operational || !a.operational)
        .map(|a| a.name.chars().count())
        .max()
        .unwrap_or(10)
        .clamp(8, 30) as u16;
    let value_w = table_area.width.saturating_sub(name_w + 3 + 2) as usize;
    let rows: Vec<TRow> = rows_idx
        .iter()
        .map(|&(ai, vi)| {
            let a = &entry.attrs[ai];
            let name = if vi == 0 {
                Span::styled(a.name.clone(), if a.operational { t.dim() } else { t.accent() })
            } else {
                Span::raw("")
            };
            let (marker, value) = match a.values.get(vi) {
                None => (Span::raw(""), Line::from(Span::styled("(no values)", t.dim()))),
                Some(v) => {
                    let shown = decode::display_value(&a.name, v);
                    let follow = matches!(v, Value::Text(s) if is_followable(&a.name, s));
                    let mut spans = vec![Span::styled(
                        truncate(&shown, value_w, ctx.sym.ellipsis),
                        if follow { t.link() } else { ratatui::style::Style::new() },
                    )];
                    if let (Value::Text(_), Some(ann)) = (v, decode::annotate(&a.name, v)) {
                        let room = value_w.saturating_sub(shown.chars().count() + 3);
                        if room > 4 {
                            spans
                                .push(Span::styled(format!("  ({})", truncate(&ann, room, ctx.sym.ellipsis)), t.dim()));
                        }
                    }
                    let marker = if follow { Span::styled(ctx.sym.follow, t.link()) } else { Span::raw("") };
                    (marker, Line::from(spans))
                }
            };
            TRow::new(vec![Cell::from(name), Cell::from(marker), Cell::from(value)])
        })
        .collect();
    let table = Table::new(rows, [Constraint::Length(name_w), Constraint::Length(2), Constraint::Fill(1)])
        .column_spacing(1)
        .row_highlight_style(t.selected(focused));
    f.render_stateful_widget(table, table_area, &mut app.entry.state);
    app.hit.right_rows = Some(table_area);
    app.hit.right_offset = app.entry.state.offset();
}

fn footer(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    if let Some(m) = &app.message
        && m.level != Level::Info
    {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(format!(" {}", m.text), ctx.theme.level(m.level)))),
            area,
        );
        return;
    }
    let tree_mode = app.results.as_ref().is_some_and(|r| r.tree.is_some());
    let pairs: Vec<(&str, &str)> = match (app.focus, app.results.is_some()) {
        (Focus::Left, true) if tree_mode => vec![
            ("↑↓", "move"),
            ("→", "expand"),
            ("←", "collapse"),
            ("f", "open"),
            ("t", "flat list"),
            ("Esc", "close"),
            ("Tab", "entry"),
            ("?", "help"),
        ],
        (Focus::Left, false) => vec![
            ("↑↓", "move"),
            ("→", "expand"),
            ("←", "collapse"),
            (":", "filter"),
            ("Tab", "entry"),
            ("/", "search"),
            ("g", "go to DN"),
            ("'", "bookmarks"),
            ("b/F", "back/fwd"),
            ("?", "help"),
            ("q", "quit"),
        ],
        (Focus::Left, true) => vec![
            ("↑↓", "move"),
            ("Enter", "open"),
            ("Esc", "close results"),
            ("n", "nested"),
            ("s/S", "sort"),
            ("c", "columns"),
            ("t", "tree"),
            ("Tab", "entry"),
            ("/", "search"),
            ("?", "help"),
            ("q", "quit"),
        ],
        (Focus::Right, _) => vec![
            ("↑↓", "move"),
            ("Enter/f", "follow DN"),
            ("v", "view value"),
            (":", "filter"),
            ("d/D", "mark/diff"),
            ("m/M", "members/groups"),
            ("o", "operational"),
            ("y/Y", "copy DN/value"),
            ("?", "help"),
        ],
    };
    let (mut line, areas) = hints_at(&pairs, ctx, area);
    app.hit.footer = areas;
    if let Some(m) = &app.message {
        line.spans.push(Span::styled(format!("   {}", m.text), ctx.theme.dim()));
    }
    f.render_widget(Paragraph::new(line), area);
}
