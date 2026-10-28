//! Rendering. Everything here is a pure function of `App` state.

mod browse;
mod popups;
mod screens;

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

use crate::app::{App, Level, Screen};
use crate::ldap::model::EntryKind;

pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;
/// Below this width the tree and entry panes stack vertically.
pub const STACK_WIDTH: u16 = 100;

pub struct Theme {
    color: bool,
}

impl Theme {
    pub fn detect() -> Theme {
        Theme { color: std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()) }
    }

    fn fg(&self, c: Color) -> Style {
        if self.color { Style::new().fg(c) } else { Style::new() }
    }

    pub fn dim(&self) -> Style {
        if self.color { Style::new().fg(Color::DarkGray) } else { Style::new().add_modifier(Modifier::DIM) }
    }
    pub fn accent(&self) -> Style {
        self.fg(Color::Cyan).add_modifier(Modifier::BOLD)
    }
    pub fn key(&self) -> Style {
        self.fg(Color::Yellow).add_modifier(Modifier::BOLD)
    }
    pub fn link(&self) -> Style {
        self.fg(Color::LightBlue)
    }
    pub fn error(&self) -> Style {
        self.fg(Color::LightRed).add_modifier(Modifier::BOLD)
    }
    pub fn warn(&self) -> Style {
        self.fg(Color::Yellow)
    }
    pub fn ok(&self) -> Style {
        self.fg(Color::Green)
    }
    pub fn selected(&self, focused: bool) -> Style {
        match (self.color, focused) {
            (true, true) => Style::new().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD),
            (true, false) => Style::new().bg(Color::DarkGray).fg(Color::White),
            (false, true) => Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            (false, false) => Style::new().add_modifier(Modifier::REVERSED),
        }
    }
    pub fn border(&self, focused: bool) -> Style {
        if focused { self.fg(Color::Cyan) } else { self.dim() }
    }
    pub fn badge(&self, level: Level) -> Style {
        match (self.color, level) {
            (true, Level::Error) => Style::new().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD),
            (true, Level::Warn) => Style::new().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD),
            (true, Level::Info) => Style::new().bg(Color::Green).fg(Color::Black).add_modifier(Modifier::BOLD),
            (false, _) => Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
        }
    }
    pub fn level(&self, level: Level) -> Style {
        match level {
            Level::Info => self.ok(),
            Level::Warn => self.warn(),
            Level::Error => self.error(),
        }
    }
    pub fn kind(&self, k: EntryKind) -> Style {
        self.fg(match k {
            EntryKind::Domain => Color::Magenta,
            EntryKind::OrgUnit => Color::Yellow,
            EntryKind::Container | EntryKind::Builtin => Color::LightYellow,
            EntryKind::User => Color::Green,
            EntryKind::Computer => Color::LightCyan,
            EntryKind::Group => Color::LightMagenta,
            EntryKind::Gpo => Color::LightBlue,
            EntryKind::Referral => Color::Red,
            EntryKind::Other => Color::Gray,
        })
    }
}

pub struct Symbols {
    pub expanded: &'static str,
    pub collapsed: &'static str,
    pub leaf: &'static str,
    pub follow: &'static str,
    pub bookmark: &'static str,
    pub ellipsis: &'static str,
    pub sep: &'static str,
    pub spinner: &'static [&'static str],
}

impl Symbols {
    pub fn pick(ascii: bool) -> Symbols {
        let utf8 = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
            .map(|s| s.to_ascii_uppercase().contains("UTF-8") || s.to_ascii_uppercase().contains("UTF8"))
            .unwrap_or(true);
        if ascii || !utf8 {
            Symbols {
                expanded: "-",
                collapsed: "+",
                leaf: " ",
                follow: "->",
                bookmark: "*",
                ellipsis: "...",
                sep: "|",
                spinner: &["|", "/", "-", "\\"],
            }
        } else {
            Symbols {
                expanded: "▾",
                collapsed: "▸",
                leaf: " ",
                follow: "→",
                bookmark: "★",
                ellipsis: "…",
                sep: "│",
                spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            }
        }
    }

    pub fn spin(&self, tick: usize) -> &'static str {
        self.spinner[(tick / 2) % self.spinner.len()]
    }
}

/// Single-letter type marker shown before tree and result rows.
pub fn kind_letter(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Domain => "D",
        EntryKind::OrgUnit => "O",
        EntryKind::Container => "C",
        EntryKind::Builtin => "B",
        EntryKind::User => "U",
        EntryKind::Computer => "M",
        EntryKind::Group => "G",
        EntryKind::Gpo => "P",
        EntryKind::Referral => "R",
        EntryKind::Other => "·",
    }
}

pub struct Ctx {
    pub theme: Theme,
    pub sym: Symbols,
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let ctx = Ctx { theme: Theme::detect(), sym: Symbols::pick(app.ascii) };
    let area = f.area();
    app.hit = crate::app::mouse::HitAreas::default();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let msg = Paragraph::new(vec![
            Line::from("Terminal too small"),
            Line::from(format!("{}×{} — need at least {MIN_WIDTH}×{MIN_HEIGHT}", area.width, area.height)),
            Line::from("q / Ctrl-C to quit"),
        ])
        .centered();
        let [mid] = Layout::vertical([Constraint::Length(3)]).flex(Flex::Center).areas(area);
        f.render_widget(msg, mid);
        return;
    }
    match &app.screen {
        Screen::Picker { .. } => screens::picker(f, app, &ctx, area),
        Screen::Login(_) => screens::login(f, app, &ctx, area),
        Screen::Connecting { .. } => screens::connecting(f, app, &ctx, area),
        Screen::Browse => browse::draw(f, app, &ctx, area),
    }
    if app.overlay.is_some() {
        popups::draw(f, app, &ctx, area);
    }
}

pub fn block<'a>(title: impl Into<Line<'a>>, focused: bool, ctx: &Ctx) -> Block<'a> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(if focused { BorderType::Thick } else { BorderType::Plain })
        .border_style(ctx.theme.border(focused))
        .title(title)
}

pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(2));
    let h = height.min(area.height.saturating_sub(2));
    let [v] = Layout::vertical([Constraint::Length(h)]).flex(Flex::Center).areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w)]).flex(Flex::Center).areas(v);
    r
}

/// Like [`hints`], also returning the screen area of each key label for mouse hit-testing.
pub fn hints_at<'a>(pairs: &[(&'a str, &'a str)], ctx: &Ctx, area: Rect) -> (Line<'a>, Vec<(Rect, String)>) {
    let line = hints(pairs, ctx);
    let mut areas = Vec::new();
    let mut x = area.x as usize + 1;
    for (i, (k, d)) in pairs.iter().enumerate() {
        if i > 0 {
            x += 2;
        }
        let kw = k.chars().count();
        let end = x + kw + 1 + d.chars().count();
        if end <= (area.x + area.width) as usize {
            areas.push((Rect::new(x as u16, area.y, (end - x) as u16, 1), k.to_string()));
        }
        x = end;
    }
    (line, areas)
}

/// Footer of `key description` pairs.
pub fn hints<'a>(pairs: &[(&'a str, &'a str)], ctx: &Ctx) -> Line<'a> {
    let mut spans = vec![Span::raw(" ")];
    for (i, (k, d)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", ctx.theme.dim()));
        }
        spans.push(Span::styled(*k, ctx.theme.key()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(*d, ctx.theme.dim()));
    }
    Line::from(spans)
}

/// Truncates to `width` display columns (approximated by chars), adding an ellipsis.
pub fn truncate(s: &str, width: usize, ellipsis: &str) -> String {
    let n = s.chars().count();
    if n <= width {
        return s.to_string();
    }
    let keep = width.saturating_sub(ellipsis.chars().count());
    format!("{}{ellipsis}", s.chars().take(keep).collect::<String>())
}

/// Renders a text input with a visible cursor.
pub fn input_line<'a>(input: &crate::app::input::TextInput, focused: bool, width: usize, ctx: &Ctx) -> Line<'a> {
    let text = input.display();
    let chars: Vec<char> = text.chars().collect();
    let cur = input.cursor().min(chars.len());
    // Scroll horizontally so the cursor stays visible.
    let start = cur.saturating_sub(width.saturating_sub(1));
    let visible: Vec<char> = chars.iter().skip(start).take(width).copied().collect();
    if !focused {
        return Line::from(visible.into_iter().collect::<String>());
    }
    let rel = cur - start;
    let before: String = visible.iter().take(rel).collect();
    let at: String = visible.get(rel).map(|c| c.to_string()).unwrap_or_else(|| " ".into());
    let after: String = visible.iter().skip(rel + 1).collect();
    let cursor_style = if ctx.theme.color {
        Style::new().bg(Color::White).fg(Color::Black)
    } else {
        Style::new().add_modifier(Modifier::REVERSED)
    };
    Line::from(vec![Span::raw(before), Span::styled(at, cursor_style), Span::raw(after)])
}

#[cfg(test)]
mod tests;
