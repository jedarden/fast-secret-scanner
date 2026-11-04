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

Run `scripts/test-forgejo-pre-receive.sh` from this repository after building
`secret-scanner`. It copies the exact canonical hook bytes from
`$HOME/declarative-config/tools/forgejo-secret-scan/pre-receive` into a local
bare repository and pushes through a Forgejo-style dispatcher. It checks that
previously accepted history is excluded, new synthetic candidates are blocked
without disclosure, clean pushes succeed, both scanners fail closed on missing
binaries, errors, and timeouts, and Forgejo and custom sibling hooks can veto
the push. Set `DECLARATIVE_CONFIG_DIR` and `FASTSCAN_BIN` if those paths differ;
the test runs the real Rust scanner with a controlled Gitleaks double to check
the pinned invocation and failure handling. It sets `SECRET_SCAN_ENABLED=1`
because content scanning is currently disabled by default for ordinary pushes.

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
Each run's result, with the journal tail on failure, is in the [event log](#event-log)
(`secret-scanner-events query --component reconcile`); the full output stays in
`journalctl --user -u secret-scanner-reconcile.service`.
The timer is eventual reconciliation. Forgejo's Git template adds a
creation-time guard that rejects a new repository's content push until the
canonical hook exists. A push-to-create attempt may leave an empty repository;
retry after the next successful timer run, or run
`rollout.sh --apply --only jedarden/NAME` to install it sooner. Verify the
running Forgejo container has `GIT_TEMPLATE_DIR` and canary both a rejected
first push and a clean push after installation. This guard affects new repos;
the complete existing-repo inventory remains a required rollout check.

## Event log

Every scanner component on a host appends to one file,
`~/.local/state/secret-scanner/events.jsonl` (directory 0700, file 0600,
rotated at 20 MiB to `events.jsonl.1`). A user timer ships new lines every
2 minutes to the fleet VictoriaLogs on iad-ci
(`https://victorialogs-iad-ci-ts.ardenone.com:8444`, tailnet only), so every
host's errors are in one queryable place.

```bash
secret-scanner-events query --since 24h                  # all hosts, central
secret-scanner-events query --since 7d --outcome error --host lab
secret-scanner-events tail                               # this host, local file
secret-scanner-events status                             # backlog and last ship
```

Use VictoriaLogs directly with LogsQL `_time:24h {source="secret-scanner"}`.
`host`, `component` and `outcome` narrow the stream.

| Component | Writer | Logged |
|---|---|---|
| `agent-hook` | `hooks/agent_hook.py` | blocks, errors (with scanner stderr), warnings, scans of 10 s or more |
| `prewrite-hook` | `hooks/prewrite_hook.py` | every denial, scanner errors (with stderr), scans of 10 s or more |
| `git-pre-commit` | `hooks/git-dispatch` | blocks (finding locations), scanner failures (with stderr), missing binary |
| `reconcile` | `secret-scanner-reconcile.service` `ExecStopPost` | every run; journal tail on failure |
| `event-log` | `scripts/install-event-log.py` | installation canaries |

Clean scans under 10 s are not logged.

Fields:
- Always: `ts`, `host`, `component`, `outcome` (`blocked`, `denied`, `error`, `warning`, `slow`, `ok`) and `msg`.
- When they apply: `repo`, `cwd`, `scanner_rc`, `scan_ms`, `duration_ms`, `agent`, `session_id`, `tool`, `hook_event`, `rules`, `finding_count`, `untracked_files`, `exec_error`, `stderr` and `findings`.

**The log never holds scanned content.** Proposed writes, commands and matched bytes are never passed to it. Captured text (`stderr`, `findings`, the block `reason`, a journal tail) is scanned again before it is written. Text that matches a rule, or that cannot be scanned, is replaced with a `[withheld: ...]` marker. Logging errors are swallowed and never change a hook decision. Set `SECRET_SCANNER_LOG=off` to disable writing, `SECRET_SCANNER_LOG_DIR` to move the file, and `SECRET_SCANNER_LOG_URL` (or `off`) to change or stop shipping.

The shipper keeps a byte cursor and the file's inode in `ship-cursor.json`. It POSTs only complete lines to `/insert/jsonline` and advances only after a 2xx. It finishes a rotated file before starting the new one. A failed run loses nothing; the next run retries. The VictoriaLogs IngressRoute (`declarative-config` `k8s/iad-ci/traefik/victorialogs-ingressroute.yml`) is host-matched, so inserts need no extra route.

Install or refresh on each host from a checkout at the released commit:

```bash
python3 scripts/install-event-log.py            # dry run: lists every file it would touch
python3 scripts/install-event-log.py --apply
```

The installer:
- Installs `scanlog.py`, `~/.local/bin/secret-scanner-events` and the `secret-scanner-log-ship` timer.
- Refreshes only components the host already has:
  - the installed agent and pre-write hook helpers;
  - the Git dispatcher at the active global `core.hooksPath`, when it is this project's dispatcher;
  - the reconcile unit.
- Never edits agent settings, Git configuration or which hooks run.
- With `--apply`, records a canary event, ships it, and fails unless the canary is found centrally.

