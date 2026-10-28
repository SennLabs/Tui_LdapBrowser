//! `--check`: connect, bind, print a RootDSE summary and exit. Useful for testing a profile
//! without starting the TUI.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;

use anyhow::{Result, bail};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::terminal;
use secrecy::SecretString;

use crate::config::{Profile, Scheme};
use crate::ldap::flavor::PAGED_RESULTS_OID;
use crate::ldap::session::{Creds, Session};
use crate::secrets::{Resolution, Secrets};

pub fn run(profile: &Profile, secrets: &Secrets) -> Result<()> {
    let creds = match secrets.resolve(profile) {
        Resolution::Anonymous => Creds::Anonymous,
        Resolution::Ready { bind_dn, password } => Creds::Simple { bind_dn, password },
        Resolution::NeedPassword { bind_dn } => {
            let pw = prompt(&format!("Password for {bind_dn}: "), true)?;
            Creds::Simple { bind_dn, password: SecretString::from(pw) }
        }
        Resolution::NeedBoth => {
            let dn = prompt("Bind DN / username: ", false)?;
            let pw = prompt("Password: ", true)?;
            Creds::Simple { bind_dn: dn, password: SecretString::from(pw) }
        }
    };

    println!("Profile:   {}", profile.name);
    println!("URL:       {}", profile.url());
    let tls = match (profile.scheme, profile.insecure_skip_verify) {
        (Scheme::Ldap, _) => "none (plain LDAP)",
        (Scheme::Ldaps, true) => "LDAPS, certificate NOT verified (insecure_skip_verify)",
        (Scheme::Ldaps, false) => "LDAPS, certificate verified",
    };
    println!("TLS:       {tls}");

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let s = match Session::connect(profile.clone(), creds).await {
            Ok(s) => s,
            Err(f) => {
                println!("FAILED:    {}", f.title);
                if let Some(h) = &f.hint {
                    println!("Hint:      {h}");
                }
                if !f.detail.is_empty() {
                    println!("Detail:    {}", f.detail);
                }
                bail!("connection check failed");
            }
        };
        println!("Bound as:  {}", s.bound_as.as_deref().unwrap_or("(anonymous)"));
        println!("Flavor:    {}", s.flavor.label());
        if let Some(v) = s.rootdse.first("vendorName") {
            println!("Vendor:    {v} {}", s.rootdse.first("vendorVersion").unwrap_or(""));
        }
        println!("Base DN:   {}", s.base_dn);
        for nc in s.rootdse.naming_contexts() {
            println!("Context:   {nc}");
        }
        println!(
            "Paging:    {}",
            if s.rootdse.supports_control(PAGED_RESULTS_OID) { "supported" } else { "not supported" }
        );
        let slot = Arc::new(AtomicI32::new(0));
        match s.list_children(&s.base_dn, None, profile.tree_child_limit, &slot).await {
            Ok(c) => println!("Children:  {}{} under base DN", c.children.len(), if c.truncated { "+" } else { "" }),
            Err(f) => println!("Children:  could not list base DN: {f}"),
        }
        s.unbind().await;
        println!("OK");
        Ok(())
    })
}

/// Reads a line from the terminal; `hidden` suppresses echo.
fn prompt(label: &str, hidden: bool) -> Result<String> {
    print!("{label}");
    std::io::stdout().flush()?;
    if !hidden {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        return Ok(s.trim_end_matches(['\r', '\n']).to_string());
    }
    terminal::enable_raw_mode()?;
    let mut s = String::new();
    let res = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow::anyhow!("cancelled"));
                }
                KeyCode::Esc => break Err(anyhow::anyhow!("cancelled")),
                KeyCode::Backspace => {
                    s.pop();
                }
                KeyCode::Char(c) => s.push(c),
                _ => {}
            },
            Ok(Event::Paste(p)) => s.push_str(&p),
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
    };
    terminal::disable_raw_mode()?;
    println!();
    res.map(|_| s)
}
