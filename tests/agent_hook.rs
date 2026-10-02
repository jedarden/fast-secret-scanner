use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn agent_hook_handles_findings_clean_errors_non_git_and_stop_loop() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "secret-scanner-agent-hook-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("temporary directory");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .expect("git init")
            .success()
    );

    let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
    fs::write(
        root.join("fixture.txt"),
        format!("service_api_token = {candidate}\n"),
    )
    .expect("synthetic candidate");

    let pre = event(&root, "PreToolUse", "git -C . commit -m test", false);
    let output = run_hook(&pre, env!("CARGO_BIN_EXE_secret-scanner"));
    assert!(output.contains("permissionDecision\":\"deny"));
    assert!(output.contains("fixture.txt:1:generic-api-key"));
    assert!(!output.contains(&candidate));

    let sensitive_name = format!("fixture-{candidate}.txt");
    fs::write(
        root.join(&sensitive_name),
        format!("service_api_token = {candidate}\n"),
    )
    .expect("synthetic candidate in filename");
    let post = event(&root, "PostToolUse", "", false);
    let output = run_hook(&post, env!("CARGO_BIN_EXE_secret-scanner"));
    assert!(output.contains("<redacted-path>:1:generic-api-key"));
    assert!(!output.contains(&candidate));
    fs::remove_file(root.join(sensitive_name)).expect("remove sensitive filename fixture");

    let read_only = event(&root, "PreToolUse", "git status --short", false);
    assert_eq!(run_hook(&read_only, "missing-scanner"), "{}");

    let stop = event(&root, "Stop", "", false);
    let output = run_hook(&stop, env!("CARGO_BIN_EXE_secret-scanner"));
    assert!(output.contains("decision\":\"block"));
    assert!(!output.contains(&candidate));
    let repeated_stop = event(&root, "Stop", "", true);
    let output = run_hook(&repeated_stop, env!("CARGO_BIN_EXE_secret-scanner"));
    assert!(output.contains("systemMessage"));
    assert!(!output.contains("decision\":\"block"));

    let error = run_hook(&pre, "missing-scanner");
    assert!(error.contains("permissionDecision\":\"deny"));
    assert!(error.contains("could not execute"));

    fs::remove_file(root.join("fixture.txt")).expect("remove fixture");
    assert_eq!(run_hook(&stop, env!("CARGO_BIN_EXE_secret-scanner")), "{}");

    fs::write(root.join("binary.dat"), [0, 1, 2, 3]).expect("write binary fixture");
    let output = run_hook(&post, env!("CARGO_BIN_EXE_secret-scanner"));
    assert!(output.contains("skipped binary input"));
    assert!(!output.contains("decision\":\"block"));
    assert_eq!(run_hook(&pre, env!("CARGO_BIN_EXE_secret-scanner")), "{}");
    fs::remove_file(root.join("binary.dat")).expect("remove binary fixture");

    let outside = std::env::temp_dir().join(format!("secret-scanner-non-git-{unique}"));
    fs::create_dir(&outside).expect("non-Git directory");
    assert_eq!(
        run_hook(
            &event(&outside, "Stop", "", false),
            env!("CARGO_BIN_EXE_secret-scanner")
        ),
        "{}"
    );
    fs::remove_dir_all(&outside).expect("remove non-Git directory");
    fs::remove_dir_all(&root).expect("remove test repository");
}

fn event(root: &Path, kind: &str, command: &str, stop_hook_active: bool) -> String {
    format!(
        "{{\"cwd\":\"{}\",\"hook_event_name\":\"{kind}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"{command}\"}},\"stop_hook_active\":{stop_hook_active}}}",
        root.display()
    )
}

fn run_hook(input: &str, scanner: &str) -> String {
    let mut process = Command::new("python3")
        .arg("hooks/agent_hook.py")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("SECRET_SCANNER_BIN", scanner)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start hook adapter");
    process
        .stdin
        .take()
        .expect("hook stdin")
        .write_all(input.as_bytes())
        .expect("write hook event");
    let output = process.wait_with_output().expect("wait for hook adapter");
    assert_eq!(output.status.code(), Some(0));
    String::from_utf8(output.stdout)
        .expect("UTF-8 hook output")
        .trim()
        .to_owned()
}
