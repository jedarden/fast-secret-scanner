use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use secret_scanner::{Scanner, scan_staged};

const USAGE: &str = "\
Usage: secret-scanner [OPTIONS] [PATH ...]

With no paths, scans only lines added to the Git index.

Options:
  --staged          scan staged additions (default)
  --tracked         scan all currently tracked files
  --stdin           scan standard input
  --path-label PATH label standard input findings with PATH
  --max-bytes N     skip explicit/tracked files larger than N bytes
  --quiet           suppress path:line:rule output
  --summary         print counts by rule to stderr
  -h, --help        show this help
  -V, --version     show the version
";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Staged,
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
        Ok(found) => {
            if found {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(message) => {
            eprintln!("secret-scanner: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let Some(options) = parse_options()? else {
        return Ok(false);
    };
    let mut scanner = Scanner::with_max_bytes(options.max_bytes);

    match options.mode {
        Mode::Staged => scan_staged(&mut scanner).map_err(|error| error.to_string())?,
        Mode::Tracked => scanner.scan_tracked().map_err(|error| error.to_string())?,
        Mode::Stdin => {
            let mut content = Vec::new();
            io::stdin()
                .read_to_end(&mut content)
                .map_err(|error| error.to_string())?;
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
    }
    Ok(!findings.is_empty())
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
