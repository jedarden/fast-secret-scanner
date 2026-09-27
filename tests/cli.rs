use std::fs;
use std::path::Path;
use std::process::Command;
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

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .status()
        .expect("execute git");
    assert!(status.success(), "git command failed: {arguments:?}");
}
