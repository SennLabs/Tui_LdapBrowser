//! File logging. The terminal belongs to the TUI, so logs never go to stdout/stderr.

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::EnvFilter;

/// Initialises daily-rotated logging (7 files kept). Returns the guard that flushes on drop,
/// and the log directory.
pub fn init(level: &str) -> anyhow::Result<(WorkerGuard, PathBuf)> {
    let dir = crate::config::default_log_dir();
    std::fs::create_dir_all(&dir)?;
    let appender = Builder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix("ldaptui")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&dir)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("ldaptui={level},ldap3=warn,warn")));
    tracing_subscriber::fmt().with_writer(writer).with_ansi(false).with_env_filter(filter).init();
    Ok((guard, dir))
}
