# Coding-agent hooks

The shared adapter in `hooks/agent_hook.py` runs `secret-scanner --worktree`
from the event's Git root. It sends at most 20 redacted `path:line:rule-id`
locations to the agent and never sends a matching value. Non-Git directories
produce no decision. A scanner execution failure is reported as a distinct
blocking error. Stop hooks continue the agent once; `stop_hook_active` prevents
an infinite continuation loop. The Git pre-commit and Forgejo pre-receive gates
remain the commit and push enforcement points.

Install a built Linux binary and merge the user-level hooks:

```bash
cargo build --release --target x86_64-unknown-linux-musl
python3 scripts/install-agent-hooks.py \
  --binary /build/fast-secret-scanner/x86_64-unknown-linux-musl/release/secret-scanner
python3 scripts/install-agent-hooks.py --apply \
  --binary /build/fast-secret-scanner/x86_64-unknown-linux-musl/release/secret-scanner
```

The installer copies the binary to `~/.local/bin/secret-scanner`, copies the
adapter to `~/.local/share/secret-scanner/agent_hook.py`, and merges three
entries into each existing user configuration. It preserves unrelated hooks:

| Event | Action |
|---|---|
| `PostToolUse` | After Bash or an edit tool, report any worktree finding to the agent. |
| `PreToolUse` | Deny a Bash `git commit` attempt when a finding remains. |
| `Stop` | Ask the agent to remove findings before finishing. |

The Codex file is `~/.codex/hooks.json`; Claude Code uses
`~/.claude/settings.json`. User-level hooks apply across local projects. Codex
requires an exact-definition trust review for new non-managed hooks: open
`/hooks` in Codex and trust the three scanner entries. A changed command needs
review again. Claude Code merges user-level and project-level hook settings.
Codex project hooks also require the project `.codex/` layer to be trusted.
Neither local user settings file automatically reaches a remote/cloud agent
environment; install the binary and hooks in that environment too.

The adapter's commit-command recognition is for early agent feedback. Git's
pre-commit hook enforces the staged scan even when a command is indirect, and
the Forgejo hook enforces novel history when local hooks are bypassed. A stop
continuation can be exhausted by an agent that cannot remediate a finding;
the Git gates still reject it.

Contracts and trust behavior were checked against the
[official OpenAI Docs for Codex hooks](https://learn.chatgpt.com/docs/hooks)
and the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks).
