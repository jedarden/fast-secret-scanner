use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use secret_scanner::{
    MAX_FILE_BYTES, MAX_PATCH_BYTES, Scanner, scan_staged, scan_staged_patch, scan_worktree,
};

const USAGE: &str = "\
Usage: secret-scanner [OPTIONS] [PATH ...]

With no paths, scans only lines added to the Git index.

Options:
  --staged          scan staged additions (default)
  --worktree        scan staged and unstaged additions plus untracked files
  --patch-stdin     scan added lines in a Git patch from standard input
  --tracked         scan all currently tracked files
  --stdin           scan standard input
  --path-label PATH label standard input findings with PATH
  --max-bytes N     maximum explicit, tracked, untracked, or stdin file size
  --quiet           suppress path:line:rule output
  --summary         print counts by rule to stderr
  -h, --help        show this help
  -V, --version     show the version
";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Staged,
    Worktree,
    PatchStdin,
    Tracked,
    Stdin,
    Paths,
}

struct Options {
    mode: Mode,
    quiet: bool,
    summary: bool,
    max_bytes: u64,
    path_label: String,
    paths: Vec<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(ScanOutcome::Clean) => ExitCode::SUCCESS,
        Ok(ScanOutcome::Findings) => ExitCode::FAILURE,
        Ok(ScanOutcome::UnsupportedBinary) => ExitCode::from(3),
        Err(message) => {
            eprintln!("secret-scanner: {message}");
            ExitCode::from(2)
        }
    }
}

enum ScanOutcome {
    Clean,
    Findings,
    UnsupportedBinary,
}

fn run() -> Result<ScanOutcome, String> {
    let Some(options) = parse_options()? else {
        return Ok(ScanOutcome::Clean);
    };
    let mut scanner = Scanner::with_max_bytes(options.max_bytes);

    match options.mode {
        Mode::Staged => scan_staged(&mut scanner).map_err(|error| error.to_string())?,
        Mode::Worktree => scan_worktree(&mut scanner).map_err(|error| error.to_string())?,
        Mode::PatchStdin => {
            let patch = read_limited(io::stdin().lock(), MAX_PATCH_BYTES)?;
            scan_staged_patch(&mut scanner, &patch).map_err(|error| error.to_string())?;
        }
        Mode::Tracked => scanner.scan_tracked().map_err(|error| error.to_string())?,
        Mode::Stdin => {
            let content = read_limited(io::stdin().lock(), options.max_bytes.min(MAX_PATCH_BYTES))?;
            scanner.scan_bytes(&options.path_label, &content);
        }
        Mode::Paths => {
            for path in &options.paths {
                scanner.scan_path(path).map_err(|error| {
                    format!(
                        "could not scan {}: {error}",
                        printable_path(&path.to_string_lossy())
                    )
                })?;
            }
        }
    }

    let skips = scanner.skips();
    let summary = scanner.summary();
    let findings = scanner.findings();
    if !options.quiet {
        for finding in &findings {
            println!(
                "{}:{}:{}",
                printable_path(&finding.path),
                finding.line,
                finding.rule
            );
        }
    }
    if options.summary {
        eprintln!("findings={}", findings.len());
        for (rule, count) in summary {
            eprintln!("{rule}={count}");
        }
        if !skips.is_empty() {
            eprintln!("skipped_oversized={}", skips.oversized);
            eprintln!("skipped_binary={}", skips.binary);
        }
    }
    if skips.oversized > 0 {
        return Err(format!(
            "incomplete scan: {} oversized input(s), {} binary input(s)",
            skips.oversized, skips.binary
        ));
    }
    if !findings.is_empty() {
        return Ok(ScanOutcome::Findings);
    }
    if skips.binary > 0 {
        eprintln!(
            "secret-scanner: {} binary input(s) need the comprehensive scanner",
            skips.binary
        );
        return Ok(ScanOutcome::UnsupportedBinary);
    }
    Ok(ScanOutcome::Clean)
}

fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>, String> {
    let mut content = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|error| error.to_string())?;
    if content.len() as u64 > limit {
        return Err("input exceeds scan byte limit".to_owned());
    }
    Ok(content)
}

fn parse_options() -> Result<Option<Options>, String> {
    let mut mode = Mode::Staged;
    let mut quiet = false;
    let mut summary = false;
    let mut max_bytes = 10_000_000_u64;
    let mut path_label = "<stdin>".to_owned();
    let mut paths = Vec::new();
    let mut arguments = env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--staged" => mode = Mode::Staged,
            "--worktree" => mode = Mode::Worktree,
            "--patch-stdin" => mode = Mode::PatchStdin,
            "--tracked" => mode = Mode::Tracked,
            "--stdin" => mode = Mode::Stdin,
            "--quiet" => quiet = true,
            "--summary" => summary = true,
            "--path-label" => {
                path_label = arguments
                    .next()
                    .ok_or_else(|| "--path-label requires a value".to_owned())?;
            }
            "--max-bytes" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--max-bytes requires a value".to_owned())?;
                max_bytes = value
                    .parse()
                    .map_err(|_| "--max-bytes must be an unsigned integer".to_owned())?;
                if max_bytes > MAX_FILE_BYTES {
                    return Err(format!(
                        "--max-bytes exceeds {MAX_FILE_BYTES} byte hard cap"
                    ));
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("secret-scanner {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--" => {
                paths.extend(arguments.map(PathBuf::from));
                break;
            }
            _ if argument.starts_with('-') => return Err(format!("unknown option: {argument}")),
            _ => paths.push(PathBuf::from(argument)),
        }
    }

    if !paths.is_empty() {
        mode = Mode::Paths;
    }
    if mode != Mode::Stdin && path_label != "<stdin>" {
        return Err("--path-label requires --stdin".to_owned());
    }

    Ok(Some(Options {
        mode,
        quiet,
        summary,
        max_bytes,
        path_label,
        paths,
    }))
}

fn printable_path(path: &str) -> String {
    path.chars()
        .flat_map(|character| match character {
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            '\\' => "\\\\".chars().collect(),
            other if other.is_control() => "?".chars().collect(),
            other => vec![other],
        })
        .collect()
}
