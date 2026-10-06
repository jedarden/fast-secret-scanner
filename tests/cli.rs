use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn curl_password_spans_remain_value_free_in_raw_and_json_text() {
    let positives = [
        candidate(),
        ["aBcD", "-", "eFgH"].concat(),
        ["abcdefghi", "+", "jklmnopqr", "+", "stuvwxyz"].concat(),
    ];
    let cases = ["word", "alpha", "ordinary", "${PASSWORD}"]
        .into_iter()
        .map(|password| (password, false))
        .chain(positives.iter().map(|password| (password.as_str(), true)));
    for (password, detected) in cases {
        let line = format!("curl --user operator:{password} https://example.invalid");
        for text in [line.clone(), format!("{{\"notes\":\"{line}\"}}")] {
            let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
                .args(["--stdin", "--spans"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start scanner");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write synthetic text");
            let result = child.wait_with_output().expect("scan synthetic text");
            assert_eq!(result.status.code(), Some(i32::from(detected)));
            let stdout = String::from_utf8(result.stdout).expect("UTF-8 output");
            if detected {
                assert!(!stdout.contains(password));
                assert!(!String::from_utf8_lossy(&result.stderr).contains(password));
                let start = text.find(password).expect("planted value");
                assert!(stdout.contains("curl-auth-user"));
                assert!(stdout.contains(&format!("\"start\":{start}")));
                assert!(stdout.contains(&format!("\"end\":{}", start + password.len())));
            } else {
                assert_eq!(stdout.trim(), "[]");
            }
        }
    }
}

#[test]
fn framed_curl_json_whitespace_and_literal_backslashes_have_exact_spans() {
    let positive = candidate();
    let mut cases = Vec::new();
    let mut passwords = vec![("alpha".to_owned(), false), (positive.clone(), true)];
    for count in 1..=4 {
        for tail in ['n', 'r', 't'] {
            passwords.push((format!("gH3{}{}jK4", "\\".repeat(count), tail), true));
        }
    }
    for (password, detected) in &passwords {
        for whitespace in ['\n', '\r', '\t'] {
            let raw =
                format!("curl --user operator:{password}{whitespace}  https://example.invalid");
            let encoded = serde_json::to_string(password).expect("encode password");
            let encoded = &encoded[1..encoded.len() - 1];
            for (document, planted) in [
                (raw.clone(), password.as_str()),
                (serde_json::to_string(&raw).expect("encode string"), encoded),
                (serde_json::json!({"notes": raw}).to_string(), encoded),
            ] {
                let start = document.find(planted).expect("planted password");
                cases.push((document, *detected, start, start + planted.len()));
            }
        }
    }
    // Invalid/truncated JSON must retain raw credential scanning.
    let invalid = format!("{{\"notes\":\"curl --user operator:{positive} trailing");
    let start = invalid.find(&positive).expect("planted");
    cases.push((invalid, true, start, start + positive.len()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start framed scanner");
    let mut framed = Vec::new();
    for (document, _, _, _) in &cases {
        framed.extend_from_slice(
            &u32::try_from(document.len())
                .expect("bounded document")
                .to_be_bytes(),
        );
        framed.extend_from_slice(document.as_bytes());
    }
    let mut input = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || input.write_all(&framed).expect("framed input"));
    let output = child.wait_with_output().expect("finish framed scanner");
    writer.join().expect("input writer");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(!stdout.contains(&positive));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&positive));
    assert_eq!(stdout.lines().count(), cases.len());
    for (response, (_, detected, start, end)) in stdout.lines().zip(cases) {
        let spans: serde_json::Value = serde_json::from_str(response).expect("span response");
        let spans = spans.as_array().expect("array");
        assert_eq!(spans.len(), usize::from(detected));
        if detected {
            assert_eq!(spans[0]["rule"], "curl-auth-user");
            assert_eq!(spans[0]["start"], start);
            assert_eq!(spans[0]["end"], end);
        }
    }
}

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
fn encoded_curl_password_in_semantic_or_encoded_label_is_redacted() {
    let password = candidate();
    let mut encoded = String::new();
    for character in password.chars() {
        write!(encoded, "\\u{:04x}", u32::from(character)).expect("encode scalar");
    }
    let raw = format!("curl --user operator:{password} https://example.invalid");
    let encoded_line = format!("curl --user operator:{encoded} https://example.invalid");
    let documents = [
        raw.clone(),
        serde_json::to_string(&raw).expect("quoted raw"),
        format!("\"{encoded_line}\""),
        format!("{{\"notes\":\"{encoded_line}\"}}"),
    ];
    for document in documents {
        for label in [
            format!("fixture-{password}.txt"),
            format!("fixture-{encoded}.txt"),
            "safe-fixture.txt".to_owned(),
        ] {
            let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
                .args(["--stdin", "--path-label", &label])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start labeled scanner");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(document.as_bytes())
                .expect("write runtime fixture");
            let output = child.wait_with_output().expect("scan labeled input");
            assert_eq!(output.status.code(), Some(1));
            assert!(
                !output
                    .stdout
                    .windows(password.len())
                    .any(|part| part == password.as_bytes())
            );
            assert!(
                !output
                    .stderr
                    .windows(password.len())
                    .any(|part| part == password.as_bytes())
            );
            let text = String::from_utf8(output.stdout).expect("UTF-8 output");
            if label == "safe-fixture.txt" {
                assert!(text.contains("safe-fixture.txt:1:curl-auth-user"));
            } else if document.contains(&encoded) || label.contains(&password) {
                assert!(text.contains("<redacted-path>:1:curl-auth-user"));
                assert!(!text.contains(&encoded));
            }
        }
    }
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

#[test]
fn skipped_and_oversized_input_is_not_reported_clean() {
    let excessive_limit = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--stdin", "--max-bytes", "536870913"])
        .output()
        .expect("reject unbounded file limit");
    assert_eq!(excessive_limit.status.code(), Some(2));

    let candidate = candidate();
    let content = format!("api_key = {candidate}\n");
    let mut stdin = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--stdin", "--max-bytes", "10"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("scan limited stdin");
    stdin
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(content.as_bytes())
        .expect("write candidate");
    let limited = stdin.wait_with_output().expect("limited result");
    assert_eq!(limited.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&limited.stderr).contains("input exceeds scan byte limit"));
    assert!(
        !limited
            .stderr
            .windows(candidate.len())
            .any(|part| part == candidate.as_bytes())
    );

    let repository = temporary_repository("incomplete");
    git(&repository, &["init", "-q"]);
    fs::write(repository.join("untracked.txt"), &content).expect("write untracked candidate");
    let worktree = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--worktree", "--max-bytes", "10", "--summary"])
        .current_dir(&repository)
        .output()
        .expect("scan limited worktree");
    assert_eq!(worktree.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&worktree.stderr).contains("skipped_oversized=1"));
    assert!(
        !worktree
            .stderr
            .windows(candidate.len())
            .any(|part| part == candidate.as_bytes())
    );

    fs::write(repository.join("binary.dat"), [0, 1, 2, 3, 4]).expect("write binary file");
    git(&repository, &["add", "binary.dat"]);
    let staged = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .current_dir(&repository)
        .output()
        .expect("scan binary patch");
    assert_eq!(staged.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&staged.stderr).contains("binary input(s)"));

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

#[test]
fn spans_locate_stdin_findings_without_printing_them() {
    let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
    let input = format!(
        "first line\nnotes: x token = {candidate} and more\nAuthorization: Bearer {candidate}\nclean = true\n"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--stdin", "--spans"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("execute scanner");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write input");
    let output = child.wait_with_output().expect("scanner exits");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("scanner output is UTF-8");
    assert!(
        !stdout.contains(&candidate),
        "spans must never print matched bytes"
    );

    // Parse the fixed-shape JSON objects without a JSON dependency.
    let mut located = Vec::new();
    for entry in stdout
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split("},{")
    {
        let field = |name: &str| -> String {
            let start =
                entry.find(&format!("\"{name}\":")).expect("field present") + name.len() + 3;
            entry[start..]
                .chars()
                .take_while(|c| *c != ',' && *c != '}')
                .collect::<String>()
                .trim_matches('"')
                .to_owned()
        };
        let start: usize = field("start").parse().expect("start offset");
        let end: usize = field("end").parse().expect("end offset");
        located.push((field("rule"), field("line"), &input[start..end]));
    }
    assert_eq!(located.len(), 2, "one span per finding: {stdout}");
    for (rule, line, bytes) in &located {
        assert_eq!(
            *bytes, candidate,
            "{rule} on line {line} spans the planted value"
        );
    }
    assert!(
        located
            .iter()
            .any(|(rule, line, _)| rule == "generic-api-key" && line == "2")
    );
    assert!(
        located
            .iter()
            .any(|(rule, line, _)| rule == "authorization-header" && line == "3")
    );

    let refused = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--spans", "--tracked"])
        .output()
        .expect("execute scanner");
    assert_eq!(refused.status.code(), Some(2), "--spans requires --stdin");
}

#[test]
fn nul_separated_documents_are_scanned_independently() {
    let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
    let documents = [
        "clean text".to_owned(),
        format!("notes: token = {candidate}"),
        // A Secret header and a data block in different documents must not
        // combine: each document starts with fresh rule state.
        "kind: Secret".to_owned(),
        ["data:\n  value: ", "QWJjZGVmR2hpSmtMbW5PcFFy"].concat(),
    ];
    let input = documents.join("\0");
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--stdin", "--spans", "--nul"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("execute scanner");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write input");
    let output = child.wait_with_output().expect("scanner exits");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("scanner output is UTF-8");
    assert!(!stdout.contains(&candidate));
    let expected_start = documents[1].find(&candidate).expect("planted");
    assert_eq!(
        stdout.trim(),
        format!(
            "[{{\"doc\":1,\"line\":1,\"rule\":\"generic-api-key\",\"start\":{expected_start},\"end\":{}}}]",
            expected_start + candidate.len()
        )
    );

    let refused = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .args(["--stdin", "--nul"])
        .stdin(Stdio::null())
        .output()
        .expect("execute scanner");
    assert_eq!(refused.status.code(), Some(2), "--nul requires --spans");
}

#[test]
fn serve_answers_each_framed_document_on_one_line() {
    use std::io::{BufRead, BufReader};
    let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
    let documents: Vec<Vec<u8>> = vec![
        b"clean".to_vec(),
        format!("token = {candidate}").into_bytes(),
        b"bin\0ary".to_vec(),
        Vec::new(),
    ];
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-scanner"))
        .arg("--serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("execute scanner");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut responses = Vec::new();
    for document in &documents {
        let length = u32::try_from(document.len()).expect("small document");
        stdin
            .write_all(&length.to_be_bytes())
            .expect("write header");
        stdin.write_all(document).expect("write document");
        stdin.flush().expect("flush");
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read response");
        assert!(
            !line.contains(&candidate),
            "serve must never write matched bytes"
        );
        responses.push(line.trim().to_owned());
    }
    drop(stdin);
    assert!(child.wait().expect("scanner exits").success());
    let start = documents[1]
        .windows(candidate.len())
        .position(|window| window == candidate.as_bytes())
        .expect("planted");
    assert_eq!(
        responses,
        [
            "[]".to_owned(),
            format!(
                "[{{\"line\":1,\"rule\":\"generic-api-key\",\"start\":{start},\"end\":{}}}]",
                start + candidate.len()
            ),
            "{\"skipped\":\"binary\"}".to_owned(),
            "[]".to_owned(),
        ]
    );
}
