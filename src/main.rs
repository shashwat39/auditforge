mod config;
mod event;
mod parser;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;

use crate::config::{Cli, Command};
use crate::parser::parse_line;

/// Reject a single input line larger than this so a corrupt log cannot
/// grow memory without bound. One mebibyte is far above a normal audit record.
const MAX_LINE_BYTES: usize = 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("auditforge: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), AppError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("auditforge {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Parse { input } => {
            let shutdown = install_shutdown_flag()?;
            if input == "-" {
                let stdin = io::stdin();
                let mut reader = BufReader::new(stdin.lock());
                process(&mut reader, false, &shutdown)
            } else {
                let mut reader = open_file(&input)?;
                process(&mut reader, false, &shutdown)
            }
        }
        Command::Run { input } => {
            if input == "-" {
                return Err(AppError::Usage(
                    "run requires a file path; use parse --input - to read stdin".to_string(),
                ));
            }
            let shutdown = install_shutdown_flag()?;
            let mut reader = open_file(&input)?;
            process(&mut reader, true, &shutdown)
        }
    }
}

fn open_file(path: &str) -> Result<BufReader<File>, AppError> {
    let file = File::open(path).map_err(|source| AppError::Io {
        context: format!("failed to open {path}"),
        source,
    })?;
    Ok(BufReader::new(file))
}

fn install_shutdown_flag() -> Result<Arc<AtomicBool>, AppError> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown)).map_err(
        |source| AppError::Io {
            context: "failed to register SIGTERM handler".to_string(),
            source,
        },
    )?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown)).map_err(
        |source| AppError::Io {
            context: "failed to register SIGINT handler".to_string(),
            source,
        },
    )?;
    Ok(shutdown)
}

fn process<R: BufRead>(
    reader: &mut R,
    follow: bool,
    shutdown: &AtomicBool,
) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut line_no: u64 = 0;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match next_line(reader).map_err(|source| AppError::Io {
            context: "failed to read input".to_string(),
            source,
        })? {
            Line::Eof => {
                if !follow || !sleep_interruptible(shutdown, Duration::from_millis(200)) {
                    break;
                }
            }
            Line::TooLong => {
                line_no += 1;
                eprintln!("auditforge: line {line_no} exceeds 1 MiB and was skipped");
            }
            Line::Text(text) => {
                line_no += 1;
                if text.trim().is_empty() {
                    continue;
                }
                let parsed = parse_line(&text);
                if !parsed.well_formed {
                    eprintln!(
                        "auditforge: malformed record at line {line_no}: not an audit record"
                    );
                }
                let json = serde_json::to_string(&parsed.event).map_err(|err| AppError::Json {
                    context: format!("failed to encode line {line_no}"),
                    source: err,
                })?;
                writeln!(out, "{json}").map_err(|source| AppError::Io {
                    context: "failed to write output".to_string(),
                    source,
                })?;
                out.flush().map_err(|source| AppError::Io {
                    context: "failed to flush output".to_string(),
                    source,
                })?;
            }
        }
    }

    out.flush().map_err(|source| AppError::Io {
        context: "failed to flush output".to_string(),
        source,
    })?;
    Ok(())
}

enum Line {
    Eof,
    Text(String),
    TooLong,
}

fn next_line<R: BufRead>(reader: &mut R) -> io::Result<Line> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return finish_buffered(buf);
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            let take = pos + 1;
            if buf.len() + take > MAX_LINE_BYTES {
                reader.consume(take);
                return Ok(Line::TooLong);
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return finish_buffered(buf);
        }
        let take = available.len();
        if buf.len() + take > MAX_LINE_BYTES {
            reader.consume(take);
            discard_until_newline(reader)?;
            return Ok(Line::TooLong);
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
    }
}

fn finish_buffered(buf: Vec<u8>) -> io::Result<Line> {
    if buf.is_empty() {
        return Ok(Line::Eof);
    }
    if buf.len() > MAX_LINE_BYTES {
        return Ok(Line::TooLong);
    }
    let text = String::from_utf8_lossy(&buf);
    let text = text.trim_end_matches(['\n', '\r']).to_string();
    Ok(Line::Text(text))
}

fn discard_until_newline<R: BufRead>(reader: &mut R) -> io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            reader.consume(pos + 1);
            return Ok(());
        }
        let take = available.len();
        reader.consume(take);
    }
}

/// Sleep in short slices so SIGTERM is noticed quickly.
/// Returns false when shutdown was requested.
fn sleep_interruptible(shutdown: &AtomicBool, total: Duration) -> bool {
    let slice = Duration::from_millis(50);
    let mut left = total;
    while !left.is_zero() {
        if shutdown.load(Ordering::Relaxed) {
            return false;
        }
        let step = if left < slice { left } else { slice };
        thread::sleep(step);
        left = left.saturating_sub(step);
    }
    !shutdown.load(Ordering::Relaxed)
}

#[derive(Debug)]
enum AppError {
    Io {
        context: String,
        source: io::Error,
    },
    Json {
        context: String,
        source: serde_json::Error,
    },
    Usage(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Io { context, source } => write!(formatter, "{context}: {source}"),
            AppError::Json { context, source } => write!(formatter, "{context}: {source}"),
            AppError::Usage(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io { source, .. } => Some(source),
            AppError::Json { source, .. } => Some(source),
            AppError::Usage(_) => None,
        }
    }
}
