#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn dispatcher_blocks_staged_candidate_and_preserves_original_hook() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "secret-scanner-git-hook-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test repository");
        fs::create_dir(root.join("hooks")).expect("dispatcher directory");
        fs::create_dir(root.join("previous")).expect("previous hook directory");
        symlink(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("hooks/git-dispatch"),
            root.join("hooks/pre-commit"),
        )
        .expect("link dispatcher");
        fs::write(
            root.join("previous/pre-commit"),
            "#!/bin/sh\ntouch original-hook-ran\n",
        )
        .expect("previous hook");
        fs::set_permissions(
            root.join("previous/pre-commit"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("make hook executable");
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.name", "scanner-test"]);
        git(
            &root,
            &["config", "user.email", "scanner-test@example.invalid"],
        );
        git(&root, &["config", "core.hooksPath", "hooks"]);
        git(
            &root,
            &["config", "secretScanner.previousHooksPath", "previous"],
        );

        let candidate = ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat();
        fs::write(root.join("fixture.txt"), format!("api_key = {candidate}\n"))
            .expect("synthetic fixture");
        git(&root, &["add", "fixture.txt"]);
        let blocked = Command::new("git")
            .args(["commit", "-q", "-m", "blocked", "--", "fixture.txt"])
            .current_dir(&root)
            .env("SECRET_SCANNER_BIN", env!("CARGO_BIN_EXE_secret-scanner"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("blocked commit");
        assert!(!blocked.status.success());
        assert!(String::from_utf8_lossy(&blocked.stderr).contains("generic-api-key"));
        assert!(!String::from_utf8_lossy(&blocked.stderr).contains(&candidate));
        assert!(!root.join("original-hook-ran").exists());

        let mut file = fs::File::create(root.join("fixture.txt")).expect("clean fixture");
        file.write_all(b"clean = true\n")
            .expect("write clean fixture");
        git(&root, &["add", "fixture.txt"]);
        let clean = Command::new("git")
            .args(["commit", "-q", "-m", "clean", "--", "fixture.txt"])
            .current_dir(&root)
            .env("SECRET_SCANNER_BIN", env!("CARGO_BIN_EXE_secret-scanner"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("clean commit");
        assert!(clean.status.success());
        assert!(root.join("original-hook-ran").exists());

        let sensitive_name = format!("fixture-{candidate}.txt");
        fs::write(
            root.join(&sensitive_name),
            format!("api_key = {candidate}\n"),
        )
        .expect("synthetic candidate in filename");
        git(&root, &["add", "--", &sensitive_name]);
        let blocked = Command::new("git")
            .args(["commit", "-q", "-m", "blocked filename"])
            .current_dir(&root)
            .env("SECRET_SCANNER_BIN", env!("CARGO_BIN_EXE_secret-scanner"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("blocked filename commit");
        assert!(!blocked.status.success());
        let stderr = String::from_utf8_lossy(&blocked.stderr);
        assert!(stderr.contains("<redacted-path>:1:generic-api-key"));
        assert!(!stderr.contains(&candidate));

        git(&root, &["reset", "--", &sensitive_name]);
        fs::remove_file(root.join(sensitive_name)).expect("remove synthetic filename");
        fs::write(root.join("binary.dat"), [0, 1, 2, 3]).expect("write binary fixture");
        git(&root, &["add", "binary.dat"]);
        let binary = Command::new("git")
            .args(["commit", "-q", "-m", "binary fixture", "--", "binary.dat"])
            .current_dir(&root)
            .env("SECRET_SCANNER_BIN", env!("CARGO_BIN_EXE_secret-scanner"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("binary commit");
        assert!(binary.status.success());
        assert!(String::from_utf8_lossy(&binary.stderr).contains("binary input skipped"));
        fs::remove_dir_all(&root).expect("remove exact test repository");
    }

    fn git(root: &Path, args: &[&str]) {
        let result = Command::new("git")
            .args(args)
            .current_dir(root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .expect("git command");
        assert!(result.success(), "git failed: {args:?}");
    }
}
