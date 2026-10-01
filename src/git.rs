use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use crate::detector::{Scanner, StagedFileState};

/// Scan lines added to the current repository's Git index.
///
/// # Errors
///
/// Returns an I/O error when Git cannot be executed or the staged diff fails.
pub fn scan_staged(scanner: &mut Scanner) -> io::Result<()> {
    scan_diff(scanner, &["--cached"])
}

/// Scan staged and unstaged additions, plus complete untracked regular files.
/// The index and working tree are never modified.
///
/// # Errors
///
/// Returns an I/O error when Git or a selected untracked file cannot be read.
pub fn scan_worktree(scanner: &mut Scanner) -> io::Result<()> {
    scan_staged(scanner)?;
    scan_diff(scanner, &[])?;
    let output = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("git ls-files --others failed"));
    }
    for raw_path in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|p| !p.is_empty())
    {
        let path = PathBuf::from(String::from_utf8_lossy(raw_path).as_ref());
        if fs::symlink_metadata(&path)?.file_type().is_file() {
            scanner.scan_path(&path)?;
        }
    }
    Ok(())
}

fn scan_diff(scanner: &mut Scanner, extra: &[&str]) -> io::Result<()> {
    let output = Command::new("git")
        .args(["-c", "core.quotePath=false", "diff"])
        .args(extra)
        .args([
            "--no-color",
            "--no-ext-diff",
            "--find-renames",
            "--unified=0",
            "--diff-filter=ACMR",
            "--",
        ])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("git diff failed"));
    }
    scan_staged_patch(scanner, &output.stdout);
    Ok(())
}

pub fn scan_staged_patch(scanner: &mut Scanner, patch: &[u8]) {
    let mut current_path: Option<String> = None;
    let mut new_line = 0_usize;
    let mut states: HashMap<String, StagedFileState> = HashMap::new();

    for raw_line in patch.split(|byte| *byte == b'\n') {
        if let Some(raw_path) = raw_line.strip_prefix(b"+++ ") {
            current_path = parse_new_path(raw_path);
            continue;
        }
        if raw_line.starts_with(b"@@ ") {
            new_line = parse_hunk_new_line(raw_line).unwrap_or(0);
            continue;
        }
        if raw_line.starts_with(b"diff --git ") {
            current_path = None;
            new_line = 0;
            states.clear();
            continue;
        }
        if new_line == 0 {
            continue;
        }
        match raw_line.first() {
            Some(b'+') => {
                if let Some(path) = current_path.as_deref() {
                    let state = states.entry(path.to_owned()).or_default();
                    scanner.scan_added_line(path, new_line, &raw_line[1..], state);
                }
                new_line = new_line.saturating_add(1);
            }
            Some(b'-' | b'\\') => {}
            Some(_) | None => {
                new_line = new_line.saturating_add(1);
            }
        }
    }
}

fn parse_new_path(raw_path: &[u8]) -> Option<String> {
    if raw_path == b"/dev/null" {
        return None;
    }
    // Git appends a tab after path headers containing spaces. It is a header
    // separator, not part of the path used for finding locations.
    let raw_path = raw_path.strip_suffix(b"\t").unwrap_or(raw_path);
    let raw_path = raw_path.strip_prefix(b"b/").unwrap_or(raw_path);
    Some(String::from_utf8_lossy(raw_path).into_owned())
}

fn parse_hunk_new_line(line: &[u8]) -> Option<usize> {
    let plus = line.windows(2).position(|window| window == b" +")? + 2;
    let digits = line[plus..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect::<Vec<_>>();
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_only_added_patch_lines_and_preserves_line_numbers() {
        let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
        let patch = format!(
            "diff --git a/config.txt b/config.txt\n--- a/config.txt\n+++ b/config.txt\n@@ -20,0 +21,2 @@\n+clean line\n+api_key = {candidate}\n"
        );
        let mut scanner = Scanner::new();
        scan_staged_patch(&mut scanner, patch.as_bytes());
        let findings = scanner.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "config.txt");
        assert_eq!(findings[0].line, 22);
        assert_eq!(findings[0].rule, "generic-api-key");
    }

    #[test]
    fn ignores_removed_lines() {
        let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
        let patch = format!(
            "diff --git a/config.txt b/config.txt\n--- a/config.txt\n+++ b/config.txt\n@@ -4 +4 @@\n-api_key = {candidate}\n+clean = true\n"
        );
        let mut scanner = Scanner::new();
        scan_staged_patch(&mut scanner, patch.as_bytes());
        assert!(scanner.findings().is_empty());
    }
}
