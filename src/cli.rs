use std::path::PathBuf;

use clap::Parser;

/// Read-only terminal browser for LDAP and LDAPS directories (Active Directory, OpenLDAP, LLDAP).
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// Path to config.json [default: ~/.config/ldaptui/config.json]
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Path to secrets.json [default: ~/.config/ldaptui/secrets.json]
    #[arg(long, short = 's', value_name = "FILE")]
    pub secrets: Option<PathBuf>,

    /// Profile to connect to (skips the profile picker)
    #[arg(long, short = 'p', value_name = "NAME")]
    pub profile: Option<String>,

    /// Log level: error, warn, info, debug, trace (RUST_LOG overrides)
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    pub log_level: String,

    /// Connect, bind, print a RootDSE summary and exit (no TUI)
    #[arg(long)]
    pub check: bool,

    /// Use ASCII-only symbols
    #[arg(long)]
    pub ascii: bool,

    /// Do not capture the mouse (terminal text selection works without Shift)
    #[arg(long)]
    pub no_mouse: bool,
}
