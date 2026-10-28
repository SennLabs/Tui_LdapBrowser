use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
};
use ratatui::crossterm::execute;

use ldaptui::app::App;
use ldaptui::cli::Cli;
use ldaptui::config::{self, Config};
use ldaptui::secrets::Secrets;
use ldaptui::{check, clipboard, logging, ui};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ldaptui: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let (_log_guard, log_dir) = logging::init(&cli.log_level).context("cannot set up logging")?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting");

    let config_path = cli.config.clone().unwrap_or_else(config::default_config_path);
    if !config_path.exists() {
        anyhow::bail!(
            "config file not found: {}\n\nCreate it from config.example.json (or pass --config FILE).\n\
             Credentials go in {} (see secrets.example.json).",
            config_path.display(),
            cli.secrets.clone().unwrap_or_else(config::default_secrets_path).display()
        );
    }
    let config = Config::load(&config_path)?;
    let secrets_path = cli.secrets.clone().unwrap_or_else(config::default_secrets_path);
    let (secrets, warnings) = Secrets::load(&secrets_path)?;
    for w in &warnings {
        tracing::warn!("{w}");
    }

    if let Some(p) = &cli.profile
        && config.profile(p).is_none()
    {
        anyhow::bail!("unknown profile \"{p}\"; available: {}", config.profile_names().join(", "));
    }

    if cli.check {
        for w in &warnings {
            eprintln!("warning: {w}");
        }
        let name = cli
            .profile
            .clone()
            .or_else(|| config.default_profile.clone())
            .or_else(|| (config.profiles.len() == 1).then(|| config.profile_names()[0].clone()))
            .context("--check needs --profile NAME (or a default_profile in the config)")?;
        return check::run(config.profile(&name).expect("validated"), &secrets);
    }

    // Only show the permissions warning; "secrets file not found" is normal when prompting.
    let ui_warnings: Vec<String> = warnings.into_iter().filter(|w| w.contains("chmod")).collect();
    let start_profile =
        cli.profile.clone().or_else(|| (config.profiles.len() == 1).then(|| config.profile_names()[0].clone()));
    let mouse = config.mouse && !cli.no_mouse;
    let mut app = App::new(config, secrets, cli.ascii, ui_warnings);
    app.load_history(config::default_state_dir().join("history.json"));
    if let Some(p) = start_profile {
        app.start_profile(&p);
    }

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    if mouse {
        let _ = execute!(std::io::stdout(), EnableMouseCapture);
    }
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(std::io::stdout(), DisableMouseCapture, DisableBracketedPaste);
        hook(info);
    }));

    let result = event_loop(&mut terminal, &mut app);

    if mouse {
        let _ = execute!(std::io::stdout(), DisableMouseCapture);
    }
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    tracing::info!("exiting");
    result.with_context(|| format!("see logs in {}", log_dir.display()))
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        app.on_tick();
        if let Some(text) = app.clipboard.take() {
            let _ = clipboard::copy(&text);
        }
        terminal.draw(|f| ui::draw(f, app))?;
        if app.should_quit {
            return Ok(());
        }
        if event::poll(Duration::from_millis(50))? {
            app.handle_event(event::read()?);
            // Drain any burst (e.g. key repeat) before redrawing.
            while event::poll(Duration::ZERO)? {
                app.handle_event(event::read()?);
                if app.should_quit {
                    return Ok(());
                }
            }
        }
    }
}
