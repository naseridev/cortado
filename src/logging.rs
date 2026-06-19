use std::io::Write;
use std::time::Instant;

use clap::builder::styling::{AnsiColor, Style};
use tokio::sync::mpsc;

const INFO_STYLE: Style = AnsiColor::Green.on_default();
const WARN_STYLE: Style = AnsiColor::Yellow.on_default();
const ERROR_STYLE: Style = AnsiColor::Red.on_default().bold();
const DEBUG_STYLE: Style = Style::new().dimmed();

pub enum LogMessage {
    Info(String),
    Warn(String),
    Error(String),
    Debug(String),
}

pub struct Logger {
    sender: mpsc::UnboundedSender<LogMessage>,
    verbose: bool,
}

impl Logger {
    pub fn new(verbose: bool) -> (Self, mpsc::UnboundedReceiver<LogMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                sender: tx,
                verbose,
            },
            rx,
        )
    }

    #[inline]
    pub fn info(&self, msg: impl Into<String>) {
        let _ = self.sender.send(LogMessage::Info(msg.into()));
    }

    #[inline]
    pub fn warn(&self, msg: impl Into<String>) {
        let _ = self.sender.send(LogMessage::Warn(msg.into()));
    }

    #[inline]
    pub fn error(&self, msg: impl Into<String>) {
        let _ = self.sender.send(LogMessage::Error(msg.into()));
    }

    #[inline]
    pub fn debug(&self, msg: impl FnOnce() -> String) {
        if self.verbose {
            let _ = self.sender.send(LogMessage::Debug(msg()));
        }
    }
}

pub fn run_log_worker(mut rx: mpsc::UnboundedReceiver<LogMessage>) {
    let start = Instant::now();
    let mut out = anstream::stderr().lock();
    while let Some(msg) = rx.blocking_recv() {
        let t = start.elapsed().as_secs_f64();
        let (level, body, style) = match &msg {
            LogMessage::Info(s) => ("INFO ", s, INFO_STYLE),
            LogMessage::Warn(s) => ("WARN ", s, WARN_STYLE),
            LogMessage::Error(s) => ("ERROR", s, ERROR_STYLE),
            LogMessage::Debug(s) => ("DEBUG", s, DEBUG_STYLE),
        };
        let _ = writeln!(
            out,
            "[{t:.3}] {open}{level}{reset} {body}",
            open = style.render(),
            reset = style.render_reset(),
        );
    }
}
