# secret-scanner delivery plan

## Phase 1 — Benchmark GIF storytelling

Owning bead: `fss-501e2518`

## Objective

Turn the README benchmark GIF from a moving comparison chart into a short,
self-explanatory story: one staged line enters, both scanners start together,
the fast local gate completes almost immediately, the comprehensive gate
finishes afterward, and the final frame explains why both layers matter.

The animation must preserve the measured claim—8 ms versus 539 ms on the same
224-byte staged patch—while explicitly stating that the on-screen motion timing
is dramatized.

## Narrative beats

1. **Setup:** Introduce one staged line and two scan lanes.
2. **Anticipation:** Hold both runners at a shared starting gate with a small
   pulse and backward wind-up.
3. **Fast action:** Launch `secret-scanner` with strong acceleration, trailing
   secondary particles, a slight overshoot, and a quick settle.
4. **First payoff:** Pop the measured 8 ms result while Gitleaks remains in
   motion, making the local-feedback benefit immediately legible.
5. **Follow-through:** Ease Gitleaks toward the same finish rather than simply
   stopping it midway.
6. **Final payoff:** Reveal 539 ms, the measured ~67x comparison, and the
   layered message: “Fast first. Comprehensive second.”
7. **Hold and loop:** Leave enough time to read the conclusion, then restart
   from a visually distinct empty-stage frame.

## Animation principles applied

- Staging and visual hierarchy through a shared start, separated lanes, and a
  single finish.
- Anticipation before launch.
- Slow-in/slow-out for Gitleaks and ease-out for the fast scanner.
- Overshoot and settle at the fast finish.
- Secondary action through restrained trails and finish ripples.
- Timing contrast to establish character without pretending the dramatized
  motion duration is the actual benchmark duration.
- Follow-through and a readable final hold before the loop resets.

## Deliverables

- [x] Versioned, text-free visual stage in `assets/`.
- [x] Deterministic FFmpeg animation in `scripts/render-benchmark-gif.sh`.
- [x] Updated `assets/benchmark.gif` referenced by the README.
- [x] Contact-sheet review of setup, launch, first finish, second finish, and
      final hold.
- [x] Secret scans, formatting checks, bead checkpoint, commit, and Forgejo
      push with GitHub mirror verification.

## Acceptance checks

- The five narrative moments are distinguishable without reading source code.
- Labels remain legible at the README's rendered width.
- Exact claims match `research/benchmark-results.tsv`.
- The footer says the motion timing is dramatized.
- The GIF loops, is 960×540, and remains reasonably sized for a README.
- Gitleaks and `secret-scanner` report no findings in the staged change.

## Phase 2 — Coding-agent hooks

Epic: `fss-83ce58cf`

### Objective

Catch likely secrets while a coding agent still owns the task, return only
actionable `path:line:rule-id` feedback, and keep the agent working until the
finding is removed. This is an agent-runtime feedback loop, not merely a Git
`pre-commit` hook.

The integration will support Codex, Claude Code, and compatible hook runtimes.
It must remain a fast first gate; pinned server-side Gitleaks stays the
authoritative comprehensive scanner.

### Required behavior

1. Scan staged and unstaged additions plus untracked files without modifying
   the Git index.
2. Run after relevant file-changing tools for early feedback.
3. Intercept attempted `git commit` commands and block when candidates exist.
4. Run when the agent tries to stop, returning findings as continuation
   instructions so the agent can remediate them.
5. Distinguish scanner outcomes:

   | Scanner status | Hook behavior |
   |---:|---|
   | `0` | Return silently and allow the agent to continue or stop. |
   | `1` | Block with redacted remediation feedback containing only locations and rule IDs. |
   | `2` | Fail closed with a distinct scanner-execution error. |

6. Detect an already-active Stop continuation through `stop_hook_active` and
   avoid an infinite loop when a finding cannot be resolved automatically.
7. Never print, persist, or pass matched values into the agent transcript.
8. Handle non-Git directories predictably and document the chosen behavior.

### Hook surfaces

- **PostToolUse:** scan after successful edit/write operations. Feedback cannot
  undo the completed write, but it can immediately direct the agent to repair
  it.
- **PreToolUse:** inspect relevant shell commands and reject `git commit` while
  the worktree contains candidates.
- **Stop:** perform the final worktree scan and continue the agent with a
  redacted remediation instruction when needed.

Configurations must use the current
[Codex hook schema](https://learn.chatgpt.com/docs/hooks) and
[Claude Code hook schema](https://code.claude.com/docs/en/hooks), resolve the
repository root from any subdirectory, and explain each runtime's hook-trust
requirements.

### Implementation beads

| Order | Bead | Scope | State |
|---:|---|---|---|
| 1 | `fss-cb646d6c` | Incremental `--worktree` scan surface | Claimed by `codex` |
| 2 | `fss-20d39d3f` | Portable hook adapter and status translation | Blocked by worktree mode |
| 3a | `fss-b4db6e11` | Codex PostToolUse, PreToolUse, and Stop integration | Blocked by adapter |
| 3b | `fss-d44eaf8d` | Claude Code PostToolUse, PreToolUse, and Stop integration | Blocked by adapter |
| 4 | `fss-addc0b6c` | Cross-agent tests, benchmarks, packaging, and rollout docs | Blocked by both integrations |
| 5 | `fss-83ce58cf` | Delivery epic | Blocked by validation |

The Codex and Claude Code integrations may proceed in parallel after the
shared adapter is complete. Resource keys prevent overlapping workers from
editing the same scanner or hook surfaces.

### Worktree scanner acceptance

- `--worktree` includes staged and unstaged added lines relative to `HEAD` and
  complete untracked text files.
- It does not stage files or otherwise mutate the repository.
- It covers unborn repositories, renames, deletions, spaces in paths, and a
  file with both staged and unstaged edits.
- Output and exit codes retain the existing redaction contract.
- Unit and CLI tests construct all synthetic candidates from fragments.
- An end-to-end benchmark records incremental hook latency.

### Adapter and integration acceptance

- One shared adapter implements the scanner-to-hook status mapping.
- Fixture tests cover clean, findings, execution error, non-Git, untracked,
  commit-attempt, Stop, and repeated-Stop inputs.
- Both agents receive actionable feedback and continue remediation without
  seeing the candidate value.
- Repository-local, user-global, managed, and plugin deployment options are
  documented where the runtime supports them.
- Hook definitions are tested from a repository subdirectory.
- Gitleaks remains documented and tested as the authoritative pushed-range
  gate.
