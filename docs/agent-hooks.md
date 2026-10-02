# Coding-agent hooks

The shared adapter in `hooks/agent_hook.py` runs `secret-scanner --worktree`
from the event's Git root. A structured write event also scans its written
regular file through standard input, which covers ignored files that Git does
not list. This second scan uses the safe label `<written-file>`; it never puts
an untrusted filename or file content in a command argument. The adapter sends
at most 20 redacted `path:line:rule-id` locations to the agent and never sends
a matching value. Non-Git directories produce no decision. A scanner execution
failure is reported as a distinct blocking error. Stop hooks continue the
agent once; `stop_hook_active` prevents an infinite continuation loop. The Git
pre-commit and Forgejo pre-receive gates remain commit and push enforcement.

Install a built Linux binary and merge the user-level hooks:

```bash
cargo build --release --target x86_64-unknown-linux-musl
python3 scripts/install-agent-hooks.py \
  --binary /build/fast-secret-scanner/x86_64-unknown-linux-musl/release/secret-scanner
python3 scripts/install-agent-hooks.py --apply \
  --binary /build/fast-secret-scanner/x86_64-unknown-linux-musl/release/secret-scanner
```

For a configured MCP or local writer whose name does not match the default
write-tool pattern, pass its exact name on every install or refresh, for
example `--write-tool mcp__workspace__persist`. Repeat the flag for multiple
tools.

The installer copies the binary to `~/.local/bin/secret-scanner`, copies the
adapter to `~/.local/share/secret-scanner/agent_hook.py`, and merges four
entries into each existing user configuration. It preserves unrelated hooks:

| Event | Action |
|---|---|
| `PostToolUse` for `Bash` | After shell commands, scan the worktree; skip plain `pwd`, `git status`, and `git diff` reads. |
| `PostToolUse` for writers | After `apply_patch`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, common MCP file writers, or an explicitly named tool, scan the worktree and any identified written file. |
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

The installer replaces its previous combined `PostToolUse` entry instead of
adding a duplicate and leaves unrelated handlers in that entry intact. Codex
reports `apply_patch` as the canonical tool name even when its matcher uses
`Edit` or `Write`. Claude Code uses `Edit` and `Write`; both products pass MCP
tool names in the `mcp__server__tool` form. The default matcher includes MCP
names beginning with `write`, `edit`, `append`, `replace`, `create`, `move`,
`rename`, `save`, or `upload`. For `apply_patch`, the adapter reads affected
paths from the patch headers; for direct tools it reads `file_path`, `path`,
`target_path`, `filename`, or `edits[].file_path`. Unrecognized schemas still
receive the worktree scan. Opaque Bash writes to ignored files cannot be
identified by path; use a structured writer for immediate ignored-file
coverage. A post-tool hook runs after the write and cannot undo it.

The adapter's commit-command recognition is for early agent feedback. Git's
pre-commit hook enforces the staged scan even when a command is indirect, and
the Forgejo hook enforces novel history when local hooks are bypassed. A stop
continuation can be exhausted by an agent that cannot remediate a finding;
the Git gates still reject it.

Contracts and trust behavior were checked against the
[official OpenAI Docs for Codex hooks](https://learn.chatgpt.com/docs/hooks)
and the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks).
