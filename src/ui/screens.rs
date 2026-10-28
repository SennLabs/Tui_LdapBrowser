//! Profile picker, login prompt and connecting screens.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};

use super::{Ctx, block, centered, hints, input_line};
use crate::app::{App, Level, MAX_LOGIN_ATTEMPTS, Screen};
use crate::config::{FlavorSetting, Scheme};

fn title_bar<'a>(ctx: &Ctx) -> Line<'a> {
    Line::from(vec![
        Span::styled(" LdapTui ", ctx.theme.accent()),
        Span::styled("read-only LDAP browser", ctx.theme.dim()),
    ])
}

fn message_line<'a>(app: &App, ctx: &Ctx) -> Line<'a> {
    match &app.message {
        Some(m) => Line::from(Span::styled(format!(" {}", m.text), ctx.theme.level(m.level))),
        None => Line::default(),
    }
}

pub fn picker(f: &mut Frame, app: &mut App, ctx: &Ctx, area: Rect) {
    let [top, main, msg, foot] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1), Constraint::Length(1)])
            .areas(area);
    f.render_widget(Paragraph::new(title_bar(ctx)), top);

    let names = app.config.profile_names();
    let items: Vec<ListItem> = names
        .iter()
        .map(|n| {
            let p = app.config.profile(n).expect("profile");
            let mut spans = vec![
                Span::styled(format!("{n:<20} "), ctx.theme.accent()),
                Span::raw(format!("{:<44} ", p.url())),
                Span::styled(
                    format!(
                        "{:<9}",
                        match p.flavor {
                            FlavorSetting::Auto => "auto",
                            FlavorSetting::Ad => "AD",
                            FlavorSetting::OpenLdap => "OpenLDAP",
                            FlavorSetting::Lldap => "LLDAP",
                        }
                    ),
                    ctx.theme.dim(),
                ),
            ];
            if p.scheme == Scheme::Ldaps && p.insecure_skip_verify {
                spans.push(Span::styled(" INSECURE TLS ", ctx.theme.badge(Level::Error)));
            } else if p.scheme == Scheme::Ldap {
                spans.push(Span::styled(" PLAIN ", ctx.theme.badge(Level::Warn)));
                spans.push(Span::raw(" ".repeat(7)));
            } else {
                spans.push(Span::styled(" TLS ", ctx.theme.badge(Level::Info)));
                spans.push(Span::raw(" ".repeat(9)));
            }
            if p.credentials.is_none() {
                spans.push(Span::styled("  anonymous", ctx.theme.dim()));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let h = (names.len() as u16 + 2).min(main.height);
    let box_area = centered(main, main.width.saturating_sub(4).min(110), h);
    let list = List::new(items)
        .block(block(" Choose a profile ", true, ctx))
        .highlight_style(ctx.theme.selected(true))
        .highlight_symbol("› ");
    if let Screen::Picker { state } = &mut app.screen {
        f.render_stateful_widget(list, box_area, state);
    }
    f.render_widget(Paragraph::new(message_line(app, ctx)), msg);
    f.render_widget(
        Paragraph::new(hints(&[("↑↓", "select"), ("Enter", "connect"), ("?", "help"), ("q", "quit")], ctx)),
        foot,
    );
}

pub fn login(f: &mut Frame, app: &App, ctx: &Ctx, area: Rect) {
    let Screen::Login(form) = &app.screen else { return };
    let [top, main, foot] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)]).areas(area);
    f.render_widget(Paragraph::new(title_bar(ctx)), top);

    let r = centered(main, 76, 13);
    let b = block(format!(" Log in to {} ", form.profile.name), true, ctx);
    let inner = b.inner(r);
    f.render_widget(b, r);
    let w = inner.width.saturating_sub(2) as usize;

    let mut lines = vec![
        Line::from(Span::styled(form.profile.url(), ctx.theme.dim())),
        Line::default(),
        Line::from(Span::styled(
            "Bind DN or username",
            if form.field == 0 { ctx.theme.accent() } else { ctx.theme.dim() },
        )),
    ];
    if form.dn_editable {
        lines.push(input_line(&form.dn, form.field == 0, w, ctx));
    } else {
        lines.push(Line::from(Span::styled(form.dn.text().to_string(), ctx.theme.dim())));
    }
    lines.push(Line::default());
    lines
        .push(Line::from(Span::styled("Password", if form.field == 1 { ctx.theme.accent() } else { ctx.theme.dim() })));
    lines.push(input_line(&form.password, form.field == 1, w, ctx));
    lines.push(Line::default());
    if let Some(e) = &form.error {
        lines.push(Line::from(Span::styled(e.clone(), ctx.theme.error())));
    } else if form.attempt > 1 {
        lines.push(Line::from(Span::styled(
            format!("attempt {} of {MAX_LOGIN_ATTEMPTS}", form.attempt),
            ctx.theme.warn(),
        )));
    }
    if form.profile.scheme == Scheme::Ldap {
        lines.push(Line::from(Span::styled("⚠ plain LDAP: the password will be sent unencrypted", ctx.theme.warn())));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

    let mut h = vec![("Enter", "log in"), ("Ctrl-N", "anonymous"), ("Esc", "back")];
    if form.dn_editable {
        h.insert(1, ("Tab", "switch field"));
    }
    f.render_widget(Paragraph::new(hints(&h, ctx)), foot);
}

pub fn connecting(f: &mut Frame, app: &App, ctx: &Ctx, area: Rect) {
    let Screen::Connecting { profile, started, .. } = &app.screen else { return };
    let r = centered(area, 70, 5);
    let lines = vec![
        Line::from(vec![
            Span::styled(ctx.sym.spin(app.tick), ctx.theme.accent()),
            Span::raw(format!(" Connecting to {} …", profile.url())),
        ]),
        Line::from(Span::styled(
            format!("{:.1}s  (timeout {}s)   Esc to cancel", started.elapsed().as_secs_f32(), profile.timeout_secs),
            ctx.theme.dim(),
        )),
    ];
    f.render_widget(Paragraph::new(lines).block(block(format!(" {} ", profile.name), true, ctx)), r);
}
