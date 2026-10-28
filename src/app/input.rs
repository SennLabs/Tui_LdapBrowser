//! Single-line text input with cursor, paste, and readline-style shortcuts.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Default)]
pub struct TextInput {
    text: String,
    /// Cursor position in chars.
    cursor: usize,
    pub masked: bool,
}

impl TextInput {
    pub fn new(text: &str) -> TextInput {
        TextInput { text: text.to_string(), cursor: text.chars().count(), masked: false }
    }

    pub fn masked() -> TextInput {
        TextInput { masked: true, ..Default::default() }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn set(&mut self, text: &str) {
        self.text = text.to_string();
        self.cursor = self.text.chars().count();
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Text as displayed (bullets when masked).
    pub fn display(&self) -> String {
        if self.masked { "•".repeat(self.text.chars().count()) } else { self.text.clone() }
    }

    fn byte_idx(&self, char_idx: usize) -> usize {
        self.text.char_indices().nth(char_idx).map(|(i, _)| i).unwrap_or(self.text.len())
    }

    pub fn insert_str(&mut self, s: &str) {
        // Pasted text may contain newlines; a single-line field keeps only the first line's worth.
        let clean: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
        let i = self.byte_idx(self.cursor);
        self.text.insert_str(i, &clean);
        self.cursor += clean.chars().count();
    }

    /// Handles editing keys. Returns true if the key was consumed.
    pub fn handle_key(&mut self, k: KeyEvent) -> bool {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let len = self.text.chars().count();
        match k.code {
            KeyCode::Char('u') if ctrl => {
                let i = self.byte_idx(self.cursor);
                self.text.replace_range(..i, "");
                self.cursor = 0;
            }
            KeyCode::Char('k') if ctrl => {
                let i = self.byte_idx(self.cursor);
                self.text.truncate(i);
            }
            KeyCode::Char('w') if ctrl => self.delete_word_back(),
            KeyCode::Backspace if ctrl || k.modifiers.contains(KeyModifiers::ALT) => self.delete_word_back(),
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = len,
            KeyCode::Char(c) if !ctrl => {
                let i = self.byte_idx(self.cursor);
                self.text.insert(i, c);
                self.cursor += 1;
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    let i = self.byte_idx(self.cursor);
                    self.text.remove(i);
                }
            }
            KeyCode::Delete => {
                if self.cursor < len {
                    let i = self.byte_idx(self.cursor);
                    self.text.remove(i);
                }
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(len),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            _ => return false,
        }
        true
    }

    fn delete_word_back(&mut self) {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.cursor;
        while i > 0 && chars[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !chars[i - 1].is_whitespace() && !matches!(chars[i - 1], ',' | '=' | '(' | ')') {
            i -= 1;
        }
        if i == self.cursor && i > 0 {
            i -= 1;
        }
        let (a, b) = (self.byte_idx(i), self.byte_idx(self.cursor));
        self.text.replace_range(a..b, "");
        self.cursor = i;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn typing_and_cursor() {
        let mut t = TextInput::default();
        for c in "héllo".chars() {
            t.handle_key(key(KeyCode::Char(c)));
        }
        t.handle_key(key(KeyCode::Left));
        t.handle_key(key(KeyCode::Backspace));
        assert_eq!(t.text(), "hélo");
        t.handle_key(key(KeyCode::Home));
        t.handle_key(key(KeyCode::Delete));
        assert_eq!(t.text(), "élo");
    }

    #[test]
    fn ctrl_shortcuts() {
        let mut t = TextInput::new("cn=foo,ou=bar baz");
        t.handle_key(ctrl('w'));
        assert_eq!(t.text(), "cn=foo,ou=bar ");
        t.handle_key(ctrl('w'));
        assert_eq!(t.text(), "cn=foo,ou=");
        t.handle_key(ctrl('u'));
        assert_eq!(t.text(), "");
    }

    #[test]
    fn paste_strips_newlines() {
        let mut t = TextInput::new("ab");
        t.handle_key(key(KeyCode::Left));
        t.insert_str("X\nY");
        assert_eq!(t.text(), "aXYb");
        assert_eq!(t.cursor(), 3);
    }

    #[test]
    fn masking() {
        let mut t = TextInput::masked();
        t.insert_str("pw");
        assert_eq!(t.display(), "••");
        assert_eq!(t.text(), "pw");
    }
}
