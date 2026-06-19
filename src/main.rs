use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::builder::styling::{AnsiColor, Style};
use clap::{Parser, Subcommand};

use cortado::logging::{Logger, run_log_worker};
use cortado::{init_config, load_config, run};

const ERROR_STYLE: Style = AnsiColor::Red.on_default().bold();
const LITERAL_STYLE: Style = Style::new().bold();

#[derive(Parser)]
#[command(
    name = "cortado",
    version,
    about = "Transparent TUN-to-SOCKS5 tunnel.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Create or reset the default configuration file.")]
    Init,
    #[command(about = "Start the tunnel; runs until interrupted with Ctrl-C.")]
    Run,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Init => cmd_init(),
        Command::Run => cmd_run(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let mut err = anstream::stderr();
            let _ = writeln!(
                err,
                "{open}cortado:{reset} {e:#}",
                open = ERROR_STYLE.render(),
                reset = ERROR_STYLE.render_reset(),
            );
            ExitCode::FAILURE
        }
    }
}

fn cmd_init() -> Result<()> {
    let path = init_config()?;
    let mut out = anstream::stdout();
    let _ = writeln!(
        out,
        "wrote default configuration to {open}{path}{reset}",
        open = LITERAL_STYLE.render(),
        path = path.display(),
        reset = LITERAL_STYLE.render_reset(),
    );
    let _ = writeln!(
        out,
        "edit it, then run {open}cortado run{reset}.",
        open = LITERAL_STYLE.render(),
        reset = LITERAL_STYLE.render_reset(),
    );
    Ok(())
}

fn cmd_run() -> Result<()> {
    require_root()?;
    let cfg = load_config()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build async runtime")?;

    let (logger, log_rx) = Logger::new(cfg.verbose);
    let worker = std::thread::spawn(|| run_log_worker(log_rx));
    let log = Arc::new(logger);

    log.info(format!(
        "cortado {} starting, proxy={} tun={}",
        env!("CARGO_PKG_VERSION"),
        cfg.proxy_addr,
        cfg.tun_name,
    ));

    let result = runtime.block_on(run(cfg, Arc::clone(&log)));
    if let Err(ref e) = result {
        log.error(format!("fatal: {e:#}"));
    }

    drop(runtime);
    drop(log);
    let _ = worker.join();
    result
}

#[cfg(unix)]
fn require_root() -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        anyhow::bail!("cortado run requires root privileges; run with sudo");
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_root() -> Result<()> {
    Ok(())
}
