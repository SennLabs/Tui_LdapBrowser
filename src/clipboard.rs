//! Clipboard via the OSC 52 terminal escape sequence. Works over SSH and inside containers,
//! provided the terminal allows it (most do; tmux needs `set -g set-clipboard on`).

use std::io::Write;

use base64::Engine;

pub fn sequence(text: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    if std::env::var_os("TMUX").is_some() {
        format!("\x1bPtmux;\x1b\x1b]52;c;{b64}\x07\x1b\\")
    } else {
        format!("\x1b]52;c;{b64}\x07")
    }
}

pub fn copy(text: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(sequence(text).as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    #[test]
    fn encodes() {
        if std::env::var_os("TMUX").is_none() {
            assert_eq!(super::sequence("hi"), "\x1b]52;c;aGk=\x07");
        }
    }
}
