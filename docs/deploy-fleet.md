# Fleet deployment

This installation has three layers: Rust before the existing local Gitleaks
hook, Codex/Claude feedback after edits, and Rust before Gitleaks in Forgejo's
pre-receive gate. The Forgejo gate covers pushes from any machine. The Rust
rules intentionally target common patterns; Gitleaks retains broader coverage.

## Workstation Git hooks

After installing the binary with `scripts/install-agent-hooks.py`, run:

```bash
python3 scripts/install-git-hooks.py
python3 scripts/install-git-hooks.py --apply
python3 scripts/install-git-hooks.py --doctor
```

The installer records the previous global `core.hooksPath` as
`secretScanner.delegateHooksPath`, installs a dispatcher under
`~/.local/share/secret-scanner/hooks`, and makes it the new global hook path.
At pre-commit, Rust scans staged additions first. When clean, any saved
repository-local hook runs, then the prior fleet dispatcher runs Gitleaks and
the repository's `.git/hooks` entry. The installer records local overrides in
`secretScanner.previousHooksPath` before changing those repositories to the
shared dispatcher. No versioned repository hook files are rewritten.

The dispatcher fails closed if the Rust binary is missing or errors. It prints
only redacted findings. `git commit --no-verify` can bypass workstation hooks;
it cannot bypass the Forgejo pre-receive gate. Re-run `--doctor` after adding
new local repositories or changing their hook configuration.

## Forgejo

Build the static Linux target, record its SHA-256, commit the release artifact,
and pin both its commit and hash in the Forgejo GitOps Application. The init
script installs it on the data PVC before a new pod becomes ready. The
pre-receive hook generates a patch over commits not already reachable from any
accepted ref, runs `secret-scanner --patch-stdin`, and then runs Gitleaks.
Missing binary, nonzero execution status, or timeout rejects the push.

Deployment source is `declarative-config`:

- `k8s/iad-ci/forgejo/forgejo-application.yml`: binary pin, checksum, install,
  and first-push Git template guard.
- `tools/forgejo-secret-scan/pre-receive`: novel-commit Rust invocation.
- `tools/forgejo-secret-scan/rollout.sh`: owner inventory and exact hook audit.
- `tools/forgejo-secret-scan/test-first-push-guard.sh`: local bare-Git creation test.

After the GitOps Application is Synced and Healthy, canary a synthetic blocked
push and a clean push. Then run `rollout.sh --apply` and a final dry run. Review
every skipped custom hook and compose it with the canonical guard. The audit
must enumerate private as well as public repositories. Reconcile again after
new repositories are created.

On the always-on workstation that owns the Forgejo credential helper, install
the checked-in user timer after `declarative-config` is checked out at
`~/declarative-config`:

```bash
install -Dm644 deploy/systemd/secret-scanner-reconcile.service \
  ~/.config/systemd/user/secret-scanner-reconcile.service
install -Dm644 deploy/systemd/secret-scanner-reconcile.timer \
  ~/.config/systemd/user/secret-scanner-reconcile.timer
systemctl --user daemon-reload
systemctl --user enable --now secret-scanner-reconcile.timer
systemctl --user start secret-scanner-reconcile.service
systemctl --user status secret-scanner-reconcile.service
```

The timer reapplies and verifies the canonical hook every 15 minutes; its
first run should exit successfully before relying on it. `rollout.sh` skips
unrecognized custom hooks and fails when an API request or hash check fails.
Review failures with `journalctl --user -u secret-scanner-reconcile.service`.
The timer is eventual reconciliation. Forgejo's Git template adds a
creation-time guard that rejects a new repository's content push until the
canonical hook exists. A push-to-create attempt may leave an empty repository;
retry after the next successful timer run, or run
`rollout.sh --apply --only jedarden/NAME` to install it sooner. Verify the
running Forgejo container has `GIT_TEMPLATE_DIR` and canary both a rejected
first push and a clean push after installation. This guard affects new repos;
the complete existing-repo inventory remains a required rollout check.
