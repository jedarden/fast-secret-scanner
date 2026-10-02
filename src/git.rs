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
    scan_staged_patch(scanner, &output.stdout)
}

/// Scan added lines in a Git-generated patch.
///
/// # Errors
///
/// Returns an error when patch headers or hunk line counts are inconsistent.
pub fn scan_staged_patch(scanner: &mut Scanner, patch: &[u8]) -> io::Result<()> {
    let mut current_path: Option<String> = None;
    let mut in_file = false;
    let mut saw_diff = false;
    let mut has_new_header = false;
    let mut hunk: Option<Hunk> = None;
    let mut states: HashMap<String, StagedFileState> = HashMap::new();

    for raw_line in patch.split(|byte| *byte == b'\n') {
        if let Some(active) = hunk.as_mut() {
            match raw_line.first() {
                Some(b'+') if active.new_remaining > 0 => {
                    let file_path = current_path.as_deref().ok_or_else(invalid_patch)?;
                    let state = states.entry(file_path.to_owned()).or_default();
                    scanner.scan_added_line(file_path, active.new_line, &raw_line[1..], state);
                    active.new_remaining -= 1;
                    active.new_line = active.new_line.checked_add(1).ok_or_else(invalid_patch)?;
                }
                Some(b'-') if active.old_remaining > 0 => active.old_remaining -= 1,
                Some(b' ') if active.old_remaining > 0 && active.new_remaining > 0 => {
                    active.old_remaining -= 1;
                    active.new_remaining -= 1;
                    active.new_line = active.new_line.checked_add(1).ok_or_else(invalid_patch)?;
                }
                Some(b'\\') => continue, // Git's "No newline at end of file" marker.
                _ => return Err(invalid_patch()),
            }
            if active.old_remaining == 0 && active.new_remaining == 0 {
                hunk = None;
            }
            continue;
        }

        if raw_line.starts_with(b"diff --git ") {
            current_path = None;
            in_file = true;
            saw_diff = true;
            has_new_header = false;
            states.clear();
            continue;
        }
        if let Some(raw_path) = raw_line.strip_prefix(b"+++ ") {
            if !in_file || has_new_header {
                return Err(invalid_patch());
            }
            current_path = parse_new_path(raw_path);
            has_new_header = true;
            continue;
        }
        if raw_line.starts_with(b"@@ ") {
            if !in_file || !has_new_header {
                return Err(invalid_patch());
            }
            let next = parse_hunk(raw_line).ok_or_else(invalid_patch)?;
            if next.old_remaining != 0 || next.new_remaining != 0 {
                hunk = Some(next);
            }
            continue;
        }
        if (raw_line.starts_with(b"+") || raw_line.starts_with(b"-")) && has_new_header {
            return Err(invalid_patch());
        }
    }
    if hunk.is_some() {
        return Err(invalid_patch());
    }
    if !saw_diff && patch.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(invalid_patch());
    }
    Ok(())
}

struct Hunk {
    old_remaining: usize,
    new_remaining: usize,
    new_line: usize,
}

fn invalid_patch() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Git patch")
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

fn parse_hunk(line: &[u8]) -> Option<Hunk> {
    let range = line.strip_prefix(b"@@ -")?;
    let old_end = range.iter().position(|byte| *byte == b' ')?;
    let old_remaining = parse_range(&range[..old_end])?.1;
    let range = range[old_end + 1..].strip_prefix(b"+")?;
    let new_end = range.iter().position(|byte| *byte == b' ')?;
    let (new_line, new_remaining) = parse_range(&range[..new_end])?;
    if !range[new_end + 1..].starts_with(b"@@") {
        return None;
    }
    Some(Hunk {
        old_remaining,
        new_remaining,
        new_line,
    })
}

fn parse_range(range: &[u8]) -> Option<(usize, usize)> {
    let comma = range.iter().position(|byte| *byte == b',');
    let number = |raw: &[u8]| std::str::from_utf8(raw).ok()?.parse().ok();
    match comma {
        Some(index) => Some((number(&range[..index])?, number(&range[index + 1..])?)),
        None => Some((number(range)?, 1)),
    }
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
        scan_staged_patch(&mut scanner, patch.as_bytes()).expect("valid patch");
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
        scan_staged_patch(&mut scanner, patch.as_bytes()).expect("valid patch");
        assert!(scanner.findings().is_empty());
    }

    #[test]
    fn header_like_added_line_does_not_hide_following_secret() {
        let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
        let patch = format!(
            "diff --git a/config.txt b/config.txt\n--- /dev/null\n+++ b/config.txt\n@@ -0,0 +1,2 @@\n+++ /dev/null\n+api_key = {candidate}\n"
        );
        let mut scanner = Scanner::new();
        scan_staged_patch(&mut scanner, patch.as_bytes()).expect("valid Git patch");
        let findings = scanner.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "config.txt");
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn rejects_truncated_hunk() {
        let patch = b"diff --git a/a b/a\n--- /dev/null\n+++ b/a\n@@ -0,0 +1,2 @@\n+one\n";
        assert!(scan_staged_patch(&mut Scanner::new(), patch).is_err());
        assert!(scan_staged_patch(&mut Scanner::new(), b"not a Git patch").is_err());
    }
}
