//! Modal overlays: help, error, value viewer, go-to-DN, tree filter, search.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Clear, List, ListItem, Paragraph, Row as TRow, Table, Wrap};

use super::{Ctx, block, centered, hints, input_line, truncate};
use crate::app::diff::{DiffRow, DiffView, RowState};
use crate::app::{App, Overlay, SCOPES, SearchKind, is_followable};
use crate::ldap::decode;
use crate::ldap::model::Value;

pub const HELP: &[(&str, &str)] = &[
    ("", "Navigation"),
    ("↑↓ j k  PgUp PgDn  Home End", "move selection"),
    ("→ l Enter", "tree: expand node · entry: follow DN / view value"),
    ("← h", "collapse node / go to parent"),
    ("Tab Shift-Tab", "switch between tree/results and entry pane"),
    ("b Backspace / F", "history back / forward"),
    ("g", "go to a DN (paste with your terminal's paste)"),
    ("", "Tree"),
    (":", "filter the selected node's children by name prefix"),
    ("r", "refresh node (and entry)"),
    ("Enter on \"… load more\"", "load the next batch of children"),
    ("", "Search & groups"),
    ("/", "search: Users · Groups · DN · Attribute · Raw filter · Saved"),
    ("Ctrl-← →", "in search: change search type"),
    ("↑↓ / Ctrl-D", "in search: recall history (prefix-filtered) / forget the recalled entry"),
    ("Ctrl-S", "in search: save the current filter to config.json (Saved tab: Enter runs it)"),
    ("m", "members of the selected group"),
    ("M", "groups the selected entry belongs to"),
    ("n", "in a groups list: toggle nested membership"),
    ("s / S / c", "in results: cycle sort column / reverse / choose columns"),
    ("t", "in a members/groups list: tree view (→ expands a group, ↻ marks a cycle)"),
    ("Esc", "cancel a running search / close results"),
    ("B / '", "bookmark the selected DN (stored in config.json) / open the bookmark list"),
    ("", "Entry"),
    (":", "filter attributes by name (Esc clears)"),
    ("d / D", "mark entry for comparison / diff against the marked entry"),
    ("f", "follow the selected DN value"),
    ("v", "view full value (hex dump for binary)"),
    ("o", "show/hide operational attributes"),
    ("e", "export: entry (LDIF/JSON/CSV), results, membership tree or tree children (JSON/CSV)"),
    ("y / Y", "copy DN / copy selected value (OSC 52)"),
    ("", "Diff view"),
    ("a / i / o", "all attributes · identity attributes · operational"),
    ("Tab ← →", "switch side for follow/copy · r refresh both"),
    ("", "Connection"),
    ("R", "reconnect"),
    ("P", "switch profile"),
    ("?", "this help"),
    ("q Ctrl-C", "quit"),
    ("", "Mouse"),
    ("click / double-click", "select · open (tree arrow expands without opening)"),
    (
        "wheel · header · right-click",
        "scroll · sort by column · context menu  (hold Shift to select text; --no-mouse disables)",
    ),
];

pub fn draw(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    let mut hit = crate::app::mouse::HitAreas::default();
    draw_inner(f, app, ctx, area, &mut hit);
    app.hit.popup = hit.popup;
    app.hit.tabs = hit.tabs;
    app.hit.popup_rows = hit.popup_rows;
    app.hit.popup_offset = hit.popup_offset;
}

fn draw_inner(f: &mut Frame, app: &App, ctx: &Ctx, area: Rect, hit: &mut crate::app::mouse::HitAreas) {
    let Some(ov) = &app.overlay else { return };
    let t = &ctx.theme;
    match ov {
        Overlay::Help { scroll } => {
            let r = centered(area, 86, HELP.len() as u16 + 4);
            let lines: Vec<Line> = HELP
                .iter()
                .map(|(k, d)| {
                    if k.is_empty() {
                        Line::from(Span::styled(*d, t.accent()))
                    } else {
                        Line::from(vec![Span::styled(format!("  {k:<30}"), t.key()), Span::raw(*d)])
                    }
                })
                .collect();
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(lines).scroll((*scroll, 0)).block(block(" Help — Esc to close ", true, ctx)),
                r,
            );
        }
        Overlay::Error { failure, scroll } => {
            let r = centered(area, 90, 14);
            let mut lines = vec![Line::from(Span::styled(failure.title.clone(), t.error())), Line::default()];
            if let Some(h) = &failure.hint {
                lines.push(Line::from(vec![Span::styled("Try: ", t.accent()), Span::raw(h.clone())]));
                lines.push(Line::default());
            }
            if !failure.detail.is_empty() {
                lines.push(Line::from(Span::styled("Details:", t.dim())));
                lines.push(Line::from(Span::styled(failure.detail.clone(), t.dim())));
            }
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0))
                    .block(block(" Error — Esc to close · y to copy ", true, ctx).border_style(t.error())),
                r,
            );
        }
        Overlay::Value { title, lines, scroll } => {
            let r = centered(area, area.width.saturating_sub(8), area.height.saturating_sub(4));
            let body: Vec<Line> = lines.iter().map(|l| Line::from(l.clone())).collect();
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(body).wrap(Wrap { trim: false }).scroll((*scroll, 0)).block(block(
                    format!(" {title} — ↑↓ scroll · y copy · Esc close "),
                    true,
                    ctx,
                )),
                r,
            );
        }
        Overlay::Goto { input, error } => {
            let r = centered(area, 100, 6);
            let b = block(" Go to DN — Enter to open · Esc to cancel ", true, ctx);
            let inner = b.inner(r);
            let mut lines = vec![input_line(input, true, inner.width as usize, ctx)];
            if let Some(e) = error {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(e.clone(), t.error())));
            }
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            f.render_widget(Paragraph::new(lines), inner);
        }
        Overlay::Filter { key, input } => {
            let r = centered(area, 70, 6);
            let name = app.tree.get(key).map(|n| n.label.clone()).unwrap_or_default();
            let b = block(format!(" Filter children of {name} "), true, ctx);
            let inner = b.inner(r);
            let lines = vec![
                input_line(input, true, inner.width as usize, ctx),
                Line::default(),
                Line::from(Span::styled("name prefix · Enter to apply (empty clears) · Esc to cancel", t.dim())),
            ];
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            f.render_widget(Paragraph::new(lines), inner);
        }
        // Rendered inline by the entry pane.
        Overlay::AttrFilter { .. } => {}
        Overlay::Diff(d) => diff(f, d, ctx, area),
        Overlay::Search(form) => search(f, app, form, ctx, area, hit),
        Overlay::BookmarkAdd { dn, input } => {
            let r = centered(area, 90, 7);
            let b = block(" Bookmark — Enter to save · Esc to cancel ", true, ctx);
            let inner = b.inner(r);
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            let [name_l, name_i, _, dn_l] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .areas(inner);
            f.render_widget(Paragraph::new(Span::styled("Name", t.accent())), name_l);
            f.render_widget(Paragraph::new(input_line(input, true, name_i.width as usize, ctx)), name_i);
            f.render_widget(
                Paragraph::new(Span::styled(truncate(dn, inner.width as usize, ctx.sym.ellipsis), t.dim())),
                dn_l,
            );
        }
        Overlay::Columns { items, state, adding } => {
            let r = centered(area, 70, (items.len() as u16 + 7).clamp(10, area.height.saturating_sub(4)));
            let b = block(" Columns ", true, ctx);
            let inner = b.inner(r);
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            let [intro, body, add_area, foot] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(if adding.is_some() { 1 } else { 0 }),
                Constraint::Length(1),
            ])
            .areas(inner);
            f.render_widget(
                Paragraph::new(Span::styled("Checked columns appear after the name, in this order.", t.dim())),
                intro,
            );
            let rows: Vec<ListItem> = items
                .iter()
                .map(|(name, on)| {
                    let mark = if *on { "[x] " } else { "[ ] " };
                    let mut spans =
                        vec![Span::styled(mark, if *on { t.ok() } else { t.dim() }), Span::raw(name.clone())];
                    if crate::app::columns::is_virtual(name) {
                        spans.push(Span::styled("  (computed)", t.dim()));
                    }
                    ListItem::new(Line::from(spans))
                })
                .collect();
            let mut st = *state;
            f.render_stateful_widget(List::new(rows).highlight_style(t.selected(true)), body, &mut st);
            hit.popup = Some(r);
            hit.popup_rows = Some(body);
            hit.popup_offset = st.offset();
            if let Some(input) = adding {
                let mut spans = vec![Span::styled("attribute: ", t.accent())];
                spans.extend(input_line(input, true, add_area.width.saturating_sub(11) as usize, ctx).spans);
                f.render_widget(Paragraph::new(Line::from(spans)), add_area);
            }
            f.render_widget(
                Paragraph::new(hints(
                    &[
                        ("Space", "toggle"),
                        ("J/K", "move"),
                        ("a", "add attribute"),
                        ("Enter", "apply"),
                        ("Esc", "cancel"),
                    ],
                    ctx,
                )),
                foot,
            );
        }
        Overlay::Export(form) => {
            let r = centered(area, 96, 12);
            let b = block(format!(" Export {} ", truncate(&form.what.describe(), 70, ctx.sym.ellipsis)), true, ctx);
            let inner = b.inner(r);
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            let [fmt_l, _, path_l, path_i, _, dec_l, _, msg_l, foot] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .areas(inner);
            let label = |text: &str, field: usize| {
                Span::styled(text.to_string(), if form.field == field { t.accent() } else { t.dim() })
            };
            hit.popup = Some(r);
            let mut fs = vec![label("Format   ", 0)];
            let mut x = fmt_l.x + 9;
            for (i, fm) in form.what.formats().iter().enumerate() {
                let s = format!(" {} ", fm.label());
                let w = s.chars().count() as u16;
                hit.tabs.push((Rect::new(x, fmt_l.y, w, 1), i));
                x += w + 1;
                fs.push(if i == form.format { Span::styled(s, t.selected(form.field == 0)) } else { Span::raw(s) });
                fs.push(Span::raw(" "));
            }
            if matches!(form.what, crate::app::export::What::Results { .. }) {
                fs.push(Span::styled("  (LDIF is for whole entries)", t.dim()));
            }
            f.render_widget(Paragraph::new(Line::from(fs)), fmt_l);
            f.render_widget(
                Paragraph::new(Line::from(vec![label("File     ", 1), Span::styled("Tab completes", t.dim())])),
                path_l,
            );
            f.render_widget(
                Paragraph::new(input_line(&form.path, form.field == 1, path_i.width as usize, ctx)),
                path_i,
            );
            let dec_note = if form.format() == crate::app::export::Format::Ldif {
                "  (LDIF is always raw)"
            } else {
                "  dates, flag names and GUIDs instead of raw values"
            };
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    label("Decoded  ", 2),
                    Span::styled(if form.decoded { "[x]" } else { "[ ]" }, if form.decoded { t.ok() } else { t.dim() }),
                    Span::styled(dec_note, t.dim()),
                ])),
                dec_l,
            );
            if let Some(e) = &form.error {
                f.render_widget(
                    Paragraph::new(Span::styled(e.clone(), if form.confirm { t.warn() } else { t.error() })),
                    msg_l,
                );
            } else if let Some(n) = &form.note {
                f.render_widget(Paragraph::new(Span::styled(n.clone(), t.dim())), msg_l);
            }
            f.render_widget(
                Paragraph::new(hints(
                    &[
                        ("Enter", "write"),
                        ("↑↓", "field"),
                        ("←→", "format / toggle"),
                        ("Tab", "complete path"),
                        ("Esc", "cancel"),
                    ],
                    ctx,
                )),
                foot,
            );
        }
        Overlay::Menu(m) => {
            let w = m.items.iter().map(|(l, _)| l.chars().count()).max().unwrap_or(10) as u16 + 4;
            let h = m.items.len() as u16 + 2;
            let x = m.at.0.min(area.width.saturating_sub(w));
            let y = m.at.1.min(area.height.saturating_sub(h));
            let r = Rect::new(x, y, w, h);
            let b = block("", true, ctx);
            let inner = b.inner(r);
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            let items: Vec<ListItem> = m.items.iter().map(|(l, _)| ListItem::new(format!(" {l}"))).collect();
            let mut st = m.state;
            f.render_stateful_widget(List::new(items).highlight_style(t.selected(true)), inner, &mut st);
            hit.popup = Some(r);
            hit.popup_rows = Some(inner);
            hit.popup_offset = st.offset();
        }
        Overlay::Bookmarks { state, rename } => {
            let list = app.bookmarks();
            let r = centered(area, 110, (list.len() as u16 + 6).clamp(8, area.height.saturating_sub(4)));
            let b = block(" Bookmarks ", true, ctx);
            let inner = b.inner(r);
            f.render_widget(Clear, r);
            f.render_widget(b, r);
            let [body, rename_area, foot] = Layout::vertical([
                Constraint::Min(1),
                Constraint::Length(if rename.is_some() { 1 } else { 0 }),
                Constraint::Length(1),
            ])
            .areas(inner);
            if list.is_empty() {
                f.render_widget(
                    Paragraph::new(Span::styled("No bookmarks yet — press B on an entry to add one.", t.dim())),
                    body,
                );
            } else {
                let name_w = list.iter().map(|b| b.name.chars().count()).max().unwrap_or(4).clamp(4, 30);
                let items: Vec<ListItem> = list
                    .iter()
                    .map(|bm| {
                        let missing = app.entry.dn.as_deref().is_some_and(|d| crate::ldap::model::dn_eq(d, &bm.dn))
                            && app.entry.error.is_some();
                        let mut spans = vec![
                            Span::styled(format!("{} ", ctx.sym.bookmark), t.warn()),
                            Span::styled(format!("{:<name_w$} ", bm.name), if missing { t.dim() } else { t.accent() }),
                            Span::styled(
                                truncate(
                                    &bm.dn,
                                    body.width.saturating_sub(name_w as u16 + 16) as usize,
                                    ctx.sym.ellipsis,
                                ),
                                t.dim(),
                            ),
                        ];
                        if missing {
                            spans.push(Span::styled("  (not found)", t.error()));
                        }
                        ListItem::new(Line::from(spans))
                    })
                    .collect();
                let mut st = *state;
                f.render_stateful_widget(List::new(items).highlight_style(t.selected(true)), body, &mut st);
                hit.popup_rows = Some(body);
                hit.popup_offset = st.offset();
            }
            hit.popup = Some(r);
            if let Some(input) = rename {
                let mut spans = vec![Span::styled("rename: ", t.accent())];
                spans.extend(input_line(input, true, rename_area.width.saturating_sub(8) as usize, ctx).spans);
                f.render_widget(Paragraph::new(Line::from(spans)), rename_area);
            }
            f.render_widget(
                Paragraph::new(hints(
                    &[("Enter", "open"), ("d", "delete"), ("e", "rename"), ("y", "copy DN"), ("Esc", "close")],
                    ctx,
                )),
                foot,
            );
        }
    }
}

fn search(
    f: &mut Frame,
    app: &App,
    form: &crate::app::SearchForm,
    ctx: &Ctx,
    area: Rect,
    hit: &mut crate::app::mouse::HitAreas,
) {
    let t = &ctx.theme;
    let r = centered(area, 100, if form.showing_saved_list() { 18 } else { 15 });
    hit.popup = Some(r);
    let b = block(" Search ", true, ctx);
    let inner = b.inner(r);
    f.render_widget(Clear, r);
    f.render_widget(b, r);
    let label = |text: &str, field: usize| {
        Span::styled(text.to_string(), if form.field == field { t.accent() } else { t.dim() })
    };

    let [kinds, _, body, err, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    let mut ks = vec![label("Type   ", 0)];
    let mut x = kinds.x + 7;
    for (i, k) in SearchKind::ALL.iter().enumerate() {
        let s = format!(" {} ", k.label());
        let w = s.chars().count() as u16;
        hit.tabs.push((Rect::new(x, kinds.y, w, 1), i));
        x += w + 1;
        ks.push(if *k == form.kind { Span::styled(s, t.selected(form.field == 0)) } else { Span::raw(s) });
        ks.push(Span::raw(" "));
    }
    f.render_widget(Paragraph::new(Line::from(ks)), kinds);

    let foot_hints: Vec<(&str, &str)> = if form.showing_saved_list() {
        let saved = app.saved_searches();
        let [slabel, list_area] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(body);
        f.render_widget(
            Paragraph::new(Line::from(vec![label("Saved  ", 1), Span::styled(form.kind.prompt(), t.dim())])),
            slabel,
        );
        if saved.is_empty() {
            f.render_widget(
                Paragraph::new(Span::styled(
                    "No saved searches. Build one in another tab and press Ctrl-S, or add \"search\": {\"saved\": [...]} to config.json.",
                    t.dim(),
                ))
                .wrap(Wrap { trim: false }),
                list_area,
            );
        } else {
            let name_w = saved.iter().map(|(s, _)| s.name.chars().count()).max().unwrap_or(4).clamp(4, 28);
            let items: Vec<ListItem> = saved
                .iter()
                .map(|(s, shared)| {
                    let mut spans = vec![Span::styled(format!("{:<name_w$} ", s.name), t.accent())];
                    let room = list_area.width.saturating_sub(name_w as u16 + 18) as usize;
                    spans.push(Span::raw(truncate(&s.filter, room, ctx.sym.ellipsis)));
                    if *shared {
                        spans.push(Span::styled("  (all profiles)", t.dim()));
                    }
                    if let Some(b) = &s.base {
                        spans.push(Span::styled(format!("  base {b}"), t.dim()));
                    }
                    ListItem::new(Line::from(spans))
                })
                .collect();
            let mut st = ratatui::widgets::ListState::default();
            st.select(Some(form.saved_sel.min(saved.len() - 1)));
            f.render_stateful_widget(List::new(items).highlight_style(t.selected(form.field == 1)), list_area, &mut st);
            hit.popup_rows = Some(list_area);
            hit.popup_offset = st.offset();
        }
        vec![("Enter", "run"), ("e", "edit"), ("d", "delete"), ("r", "rename"), ("Ctrl-←→", "type"), ("Esc", "cancel")]
    } else {
        let [qlabel, q, _, blabel, base, _, scope] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(body);
        let prompt = match &form.template {
            Some((name, filter)) => format!("text for {{q}} in \"{name}\": {filter}"),
            None => form.kind.prompt().to_string(),
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                label("Search ", 1),
                Span::styled(truncate(&prompt, qlabel.width.saturating_sub(8) as usize, ctx.sym.ellipsis), t.dim()),
            ])),
            qlabel,
        );
        f.render_widget(Paragraph::new(input_line(&form.query, form.field == 1, q.width as usize, ctx)), q);

        let base_note = if form.kind == SearchKind::Dn { " (not used for DN lookups)" } else { "" };
        f.render_widget(
            Paragraph::new(Line::from(vec![label("Base   ", 2), Span::styled(base_note, t.dim())])),
            blabel,
        );
        f.render_widget(Paragraph::new(input_line(&form.base, form.field == 2, base.width as usize, ctx)), base);

        let mut ss = vec![label("Scope  ", 3)];
        for (i, (_, name)) in SCOPES.iter().enumerate() {
            let s = format!(" {name} ");
            ss.push(if i == form.scope { Span::styled(s, t.selected(form.field == 3)) } else { Span::raw(s) });
            ss.push(Span::raw(" "));
        }
        f.render_widget(Paragraph::new(Line::from(ss)), scope);
        vec![
            ("Enter", "search"),
            ("Tab", "next field"),
            ("Ctrl-←→", "type"),
            ("↑↓", "history"),
            ("Ctrl-S", "save"),
            ("Esc", "cancel"),
        ]
    };

    if let Some(e) = &form.error {
        f.render_widget(Paragraph::new(Span::styled(e.clone(), t.error())), err);
    }
    f.render_widget(Paragraph::new(hints(&foot_hints, ctx)), foot);

    // Save / rename prompt on top of the dialog.
    if let Some(sub) = &form.sub {
        let (title, input, location) = match sub {
            crate::app::SubPrompt::Save { name, shared } => (" Save search as ", name, Some(*shared)),
            crate::app::SubPrompt::Rename { name, .. } => (" Rename saved search ", name, None),
        };
        let pr = centered(area, 70, 7);
        let pb = block(title, true, ctx);
        let pinner = pb.inner(pr);
        f.render_widget(Clear, pr);
        f.render_widget(pb, pr);
        let [name_l, loc_l, _, hint_l] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(pinner);
        let mut spans = vec![Span::styled("Name      ", t.accent())];
        spans.extend(input_line(input, true, name_l.width.saturating_sub(10) as usize, ctx).spans);
        f.render_widget(Paragraph::new(Line::from(spans)), name_l);
        if let Some(shared) = location {
            let pick = |on: bool, s: &str| {
                if on { Span::styled(format!(" {s} "), t.selected(true)) } else { Span::raw(format!(" {s} ")) }
            };
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("Store in  ", t.dim()),
                    pick(!shared, "this profile"),
                    Span::raw(" "),
                    pick(shared, "all profiles"),
                    Span::styled("   (Tab switches)", t.dim()),
                ])),
                loc_l,
            );
        }
        f.render_widget(
            Paragraph::new(Line::from(Span::styled("Enter to save into config.json · Esc to cancel", t.dim()))),
            hint_l,
        );
    }
}

fn diff(f: &mut Frame, d: &DiffView, ctx: &Ctx, area: Rect) {
    let t = &ctx.theme;
    let r = centered(area, area.width.saturating_sub(4), area.height.saturating_sub(2));
    let (diffs, total) = d.counts();
    let mut title = vec![Span::raw(" Diff "), Span::styled(format!("{diffs} of {total} attributes differ "), t.dim())];
    if !d.only_differences {
        title.push(Span::styled("· all ", t.dim()));
    }
    if d.show_operational {
        title.push(Span::styled("+operational ", t.dim()));
    }
    if !d.filter.is_empty() {
        title.push(Span::styled(format!("· filter: {} ", d.filter), t.accent()));
    }
    let b = block(Line::from(title), true, ctx);
    let inner = b.inner(r);
    f.render_widget(Clear, r);
    f.render_widget(b, r);
    let [head, table_area, filter_area, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(if d.editing.is_some() { 1 } else { 0 }),
        Constraint::Length(1),
    ])
    .areas(inner);

    let name_w = d.attrs.iter().map(|a| a.name.chars().count()).max().unwrap_or(10).clamp(8, 28) as u16;
    let side_w = inner.width.saturating_sub(name_w + 2) / 2;
    let value_w = side_w.saturating_sub(1) as usize;
    let side_style = |s: usize| if d.side == s { t.accent() } else { t.dim() };
    let heads = vec![
        Line::from(vec![
            Span::raw(" ".repeat(name_w as usize + 1)),
            Span::styled(truncate(&format!("{} (marked)", d.left.dn), value_w, ctx.sym.ellipsis), side_style(0)),
        ]),
        Line::from(vec![
            Span::raw(" ".repeat(name_w as usize + 1 + side_w as usize)),
            Span::styled(truncate(&format!("{} (current)", d.right.dn), value_w, ctx.sym.ellipsis), side_style(1)),
        ]),
    ];
    f.render_widget(Paragraph::new(heads), head);

    let cell = |a: &crate::app::diff::DiffAttr, v: Option<&Value>, differs: bool| -> Cell<'static> {
        match v {
            None => Cell::from(Span::styled(if differs { "—" } else { "" }, t.dim())),
            Some(v) => {
                let shown = decode::display_value(&a.name, v);
                let follow = matches!(v, Value::Text(s) if is_followable(&a.name, s));
                let style = if differs {
                    t.warn()
                } else if follow {
                    t.link()
                } else if a.state == RowState::Equal {
                    t.dim()
                } else {
                    Style::new()
                };
                Cell::from(Span::styled(truncate(&shown, value_w, ctx.sym.ellipsis), style))
            }
        }
    };
    let rows: Vec<TRow> = d
        .rows()
        .into_iter()
        .map(|row| match row {
            DiffRow::IdentityHeader(n) => TRow::new(vec![
                Cell::from(Span::styled(if d.show_identity { ctx.sym.expanded } else { ctx.sym.collapsed }, t.dim())),
                Cell::from(Span::styled(
                    format!(
                        "{n} identity attribute{} (always differ) — i to {}",
                        if n == 1 { "" } else { "s" },
                        if d.show_identity { "hide" } else { "show" }
                    ),
                    t.dim(),
                )),
                Cell::from(""),
            ]),
            DiffRow::Value(ai, vi) => {
                let a = &d.attrs[ai];
                let name = if vi == 0 {
                    let style = match a.state {
                        RowState::Equal => t.dim(),
                        RowState::OnlyLeft | RowState::OnlyRight | RowState::Differs => t.accent(),
                    };
                    Span::styled(a.name.clone(), style)
                } else {
                    Span::raw("")
                };
                let differs = vi >= a.shared;
                TRow::new(vec![Cell::from(name), cell(a, a.left.get(vi), differs), cell(a, a.right.get(vi), differs)])
            }
        })
        .collect();
    let widths = [Constraint::Length(name_w), Constraint::Length(side_w), Constraint::Length(side_w)];
    let mut state = d.state;
    if rows.is_empty() {
        let msg = if d.only_differences { "No differences." } else { "Nothing to show." };
        f.render_widget(Paragraph::new(Span::styled(msg, t.dim())), table_area);
    } else {
        let table = Table::new(rows, widths).column_spacing(1).row_highlight_style(t.selected(true));
        f.render_stateful_widget(table, table_area, &mut state);
    }
    if let Some(input) = &d.editing {
        let mut spans = vec![Span::styled("filter: ", t.accent())];
        spans.extend(input_line(input, true, filter_area.width.saturating_sub(8) as usize, ctx).spans);
        spans.push(Span::styled("   Enter keep · Esc clear", t.dim()));
        f.render_widget(Paragraph::new(Line::from(spans)), filter_area);
    }
    f.render_widget(
        Paragraph::new(hints(
            &[
                ("a", if d.only_differences { "all" } else { "differences" }),
                ("i", "identity"),
                ("o", "operational"),
                (":", "filter"),
                ("Tab", "side"),
                ("f", "follow"),
                ("y/Y", "copy"),
                ("r", "refresh"),
                ("Esc", "close"),
            ],
            ctx,
        )),
        foot,
    );
}
