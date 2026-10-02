use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn staged_cli_rejects_without_printing_the_value() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after Unix epoch")
        .as_nanos();
    let repository = std::env::temp_dir().join(format!(
        "secret-scanner-cli-test-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&repository).expect("create temporary repository");
    fs::create_dir(repository.join("hooks")).expect("create empty hooks directory");

    git(&repository, &["init", "-q"]);
    git(&repository, &["config", "core.hooksPath", "hooks"]);
    git(&repository, &["config", "user.name", "scanner-test"]);
    git(
        &repository,
        &["config", "user.email", "scanner-test@example.invalid"],
    );
    fs::write(repository.join("fixture.txt"), b"clean = true\n").expect("write baseline");
    git(&repository, &["add", "fixture.txt"]);
    git(&repository, &["commit", "-q", "-m", "baseline"]);

    let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
    fs::write(
        repository.join("fixture.txt"),
        format!("clean = true\nservice_api_token = {candidate}\n"),
    )
    .expect("write staged candidate");
    git(&repository, &["add", "fixture.txt"]);

    let output = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .current_dir(&repository)
        .output()
        .expect("execute scanner");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("scanner output is UTF-8");
    assert!(stdout.contains("fixture.txt:2:generic-api-key"));
    assert!(!stdout.contains(&candidate));

    fs::remove_dir_all(&repository).expect("remove exact temporary repository");
}

#[test]
fn worktree_catches_staged_unstaged_and_untracked_candidates() {
    let repository = temporary_repository("worktree");
    git(&repository, &["init", "-q"]);
    git(&repository, &["config", "core.hooksPath", "hooks"]);
    git(&repository, &["config", "user.name", "scanner-test"]);
    git(
        &repository,
        &["config", "user.email", "scanner-test@example.invalid"],
    );
    fs::create_dir(repository.join("hooks")).expect("hooks directory");
    fs::write(repository.join("staged file.txt"), "clean\n").expect("baseline");
    git(&repository, &["add", "staged file.txt"]);
    git(&repository, &["commit", "-q", "-m", "baseline"]);

    let candidate = candidate();
    fs::write(
        repository.join("staged file.txt"),
        format!("clean\napi_key = {candidate}\n"),
    )
    .expect("staged candidate");
    git(&repository, &["add", "staged file.txt"]);
    fs::write(
        repository.join("staged file.txt"),
        "clean\napi_key = removed\n",
    )
    .expect("unstaged removal");
    fs::write(
        repository.join("untracked file.txt"),
        format!("api_key = {candidate}\n"),
    )
    .expect("untracked candidate");

    let output = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .arg("--worktree")
        .current_dir(&repository)
        .output()
        .expect("execute worktree scanner");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("staged file.txt:2:generic-api-key"));
    assert!(stdout.contains("untracked file.txt:1:generic-api-key"));
    assert!(!stdout.contains(&candidate));
    fs::remove_dir_all(&repository).expect("remove test repository");
}

#[test]
fn staged_checkpoint_rename_scans_only_new_records() {
    let repository = temporary_repository("checkpoint-rename");
    git(&repository, &["init", "-q"]);
    git(&repository, &["config", "core.hooksPath", "/dev/null"]);
    git(&repository, &["config", "user.name", "scanner-test"]);
    git(
        &repository,
        &["config", "user.email", "scanner-test@example.invalid"],
    );
    let directory = repository.join(".beads/checkpoint/objects");
    fs::create_dir_all(&directory).expect("checkpoint directory");
    let old = ".beads/checkpoint/objects/old.jsonl";
    let new = ".beads/checkpoint/objects/new.jsonl";
    let inherited = candidate();
    let mut baseline = String::new();
    for index in 0..20 {
        writeln!(baseline, "record {index}: ordinary checkpoint text")
            .expect("append baseline record");
    }
    writeln!(baseline, "api_key = {inherited}").expect("append inherited candidate");
    fs::write(repository.join(old), baseline).expect("baseline checkpoint");
    git(&repository, &["add", old]);
    git(&repository, &["commit", "-q", "-m", "baseline", "--", old]);

    git(&repository, &["mv", old, new]);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(repository.join(new))
        .expect("renamed checkpoint");
    writeln!(file, "record 21: benign new event").expect("append benign event");
    git(&repository, &["add", new]);
    let clean = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .current_dir(&repository)
        .output()
        .expect("scan checkpoint rename");
    assert_eq!(
        clean.status.code(),
        Some(0),
        "unchanged records stay inherited"
    );

    let added = candidate();
    writeln!(file, "service_api_token = {added}").expect("append synthetic secret");
    git(&repository, &["add", new]);
    let blocked = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .current_dir(&repository)
        .output()
        .expect("scan newly added record");
    assert_eq!(blocked.status.code(), Some(1));
    let stdout = String::from_utf8(blocked.stdout).expect("UTF-8 scanner output");
    assert!(stdout.contains("new.jsonl:23:generic-api-key"));
    assert!(!stdout.contains(&added));
    fs::remove_dir_all(&repository).expect("remove temporary repository");
}

#[test]
fn worktree_covers_unborn_repo_and_patch_stdin_covers_commit_patch() {
    let repository = temporary_repository("unborn");
    git(&repository, &["init", "-q"]);
    let candidate = candidate();
    fs::write(
        repository.join("new.txt"),
        format!("service_api_token = {candidate}\n"),
    )
    .expect("untracked candidate");
    let output = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .arg("--worktree")
        .current_dir(&repository)
        .output()
        .expect("scan unborn repository");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("new.txt:1:generic-api-key"));

    let patch = format!(
        "diff --git a/new.txt b/new.txt\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+service_api_token = {candidate}\n"
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .arg("--patch-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn patch scanner");
    process
        .stdin
        .take()
        .expect("stdin")
        .write_all(patch.as_bytes())
        .expect("write synthetic patch");
    let output = process.wait_with_output().expect("wait for patch scanner");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("new.txt:1:generic-api-key"));
    assert!(!stdout.contains(&candidate));
    fs::remove_dir_all(&repository).expect("remove test repository");
}

#[test]
fn git_generated_header_like_added_line_cannot_hide_a_candidate() {
    let repository = temporary_repository("header-like-added-line");
    git(&repository, &["init", "-q"]);
    let candidate = candidate();
    fs::write(
        repository.join("fixture.txt"),
        format!("++ /dev/null\napi_key = {candidate}\n"),
    )
    .expect("write header-like added line");
    git(&repository, &["add", "fixture.txt"]);

    for mode in [None, Some("--worktree")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secret-scanner"));
        if let Some(mode) = mode {
            command.arg(mode);
        }
        let output = command
            .current_dir(&repository)
            .output()
            .expect("scan Git additions");
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stdout).contains("fixture.txt:2:generic-api-key"));
        assert!(
            !output
                .stdout
                .windows(candidate.len())
                .any(|part| part == candidate.as_bytes())
        );
    }

    let patch = Command::new("git")
        .args(["diff", "--cached", "--unified=0", "--", "fixture.txt"])
        .current_dir(&repository)
        .output()
        .expect("generate real Git patch")
        .stdout;
    let mut scanner = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .arg("--patch-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("scan patch");
    scanner
        .stdin
        .take()
        .expect("scanner stdin")
        .write_all(&patch)
        .expect("write patch");
    let output = scanner.wait_with_output().expect("patch scan result");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture.txt:2:generic-api-key"));
    assert!(
        !output
            .stdout
            .windows(candidate.len())
            .any(|part| part == candidate.as_bytes())
    );

    fs::remove_dir_all(&repository).expect("remove test repository");
}

#[test]
fn matched_value_in_filename_or_stdin_label_is_redacted() {
    let repository = temporary_repository("path-redaction");
    git(&repository, &["init", "-q"]);
    let candidate = candidate();
    let filename = format!("fixture-{candidate}.txt");
    let content = format!("api_key = {candidate}\n");
    fs::write(repository.join(&filename), &content).expect("write synthetic candidate");
    git(&repository, &["add", "--", &filename]);

    let staged = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .current_dir(&repository)
        .output()
        .expect("scan staged filename");
    assert_eq!(staged.status.code(), Some(1));
    let output = String::from_utf8(staged.stdout).expect("UTF-8 output");
    assert!(output.contains("<redacted-path>:1:generic-api-key"));
    assert!(!output.contains(&candidate));

    let provider_shaped = ["ghp_", &candidate, "Z4rP"].concat();
    let unrelated_name = format!("unrelated-{provider_shaped}.txt");
    fs::write(repository.join(&unrelated_name), &content)
        .expect("write candidate under sensitive-shaped filename");
    git(&repository, &["add", "--", &unrelated_name]);
    let staged = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .current_dir(&repository)
        .output()
        .expect("scan sensitive-shaped filename");
    assert_eq!(staged.status.code(), Some(1));
    assert!(
        !staged
            .stdout
            .windows(provider_shaped.len())
            .any(|part| part == provider_shaped.as_bytes())
    );

    let mut stdin = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--stdin", "--path-label", &filename])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("scan labeled stdin");
    stdin
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(content.as_bytes())
        .expect("write candidate");
    let labeled = stdin.wait_with_output().expect("stdin result");
    assert_eq!(labeled.status.code(), Some(1));
    let output = String::from_utf8(labeled.stdout).expect("UTF-8 output");
    assert!(output.contains("<redacted-path>:1:generic-api-key"));
    assert!(!output.contains(&candidate));

    fs::remove_dir_all(&repository).expect("remove test repository");
}

fn temporary_repository(label: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after Unix epoch")
        .as_nanos();
    let repository = std::env::temp_dir().join(format!(
        "secret-scanner-{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&repository).expect("create temporary repository");
    repository
}

fn candidate() -> String {
    ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat()
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .status()
        .expect("execute git");
    assert!(status.success(), "git command failed: {arguments:?}");
}
