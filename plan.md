# secret-scanner delivery plan

## Release-blocking curl password correction — 2026-10-06

Owner: `fss-2272b3b4`, linked to bead-rs release owner `beadrs-b3059276`.

- Qualify the password alone; usernames cannot supply missing credential evidence.
- Preserve opaque credential positives, multiline curl context, exact password
  spans and value-free raw/JSON-text output; reject short/prose/placeholder controls.
- Update coverage, run formatting, all-feature Clippy, all tests, release build
  and the staged end-to-end benchmark before committing scanner 0.2.8.
- Install checksum-verified scanner bytes only on codinghome and lab for the
  bead-rs parity gate. Do not activate server/global hooks or scrub real data.
- Re-run the application scan with the corrected organization scanner. Existing
  findings require independent dispositions; a rule correction is not a blanket
  false-positive declaration or permission to clear quarantine manually.
- Independent review caught an opaque alphabetic separator regression and an
  inherited JSON multiline boundary defect. Correct both with explicit controls:
  validated complete JSON, semantic password evidence, exact encoded spans,
  literal backslash preservation and ordinary raw fallback on invalid JSON.
  The application supplies a fully quoted second JSON view under its reviewed
  organization-scanner contract; no new framing protocol or scanner option.

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

## Phase 3 — Fleet protection for `jedarden/*`

Decision: [ADR 0001](docs/adr/0001-fleet-secret-scan.md).

The completion condition is a verified Forgejo pre-receive hook on every
`jedarden/*` repository, including private repositories and future new repos;
the workstation and agent hooks are early-feedback layers. The server gate
must reject novel commits before refs move, even when a contributor bypasses
local hooks. The existing pinned Gitleaks scan remains in the gate.

| Order | Bead | Scope |
|---:|---|---|
| 1 | `fss-cb646d6c` | Incremental worktree scan |
| 2 | `fss-3ae356e3` | Added-line scan from novel-commit patch stream |
| 3 | `fss-3d6f65a2` | Pinned binary and fleet Git pre-commit installation, including local overrides |
| 4 | `fss-3aa3e0b6` | GitOps runtime and Forgejo pre-receive rollout |
| 5 | `fss-5f007601` | Full owner inventory, canary, and fleet audit |
| 6 | `fss-44aec3bd` | Recurring new-repository reconciliation and documented first-push boundary |

### Required acceptance

- Rust scans additions in each novel commit, with no matched text in any
  output. Scanner failures and timeouts reject a push.
- A checksum-verified, pinned Linux binary is present on Forgejo's data PVC
  before the server hook begins calling it. The relevant ArgoCD Application is
  Synced and Healthy after the GitOps change.
- Local Git pre-commit runs Rust first, then the existing Gitleaks policy. The
  four known `core.hooksPath` overrides preserve their existing hooks and run
  Rust. The installer audits newly discovered overrides.
- Codex and Claude Code user-level hooks run after edits, before commit
  attempts, and at Stop. Hook trust and bypass limits are documented.
- Enumerate every repository owned by `jedarden` through Forgejo pagination;
  compare every live hook to the canonical version. Install or update fleet
  hooks, never overwrite an unrecognized custom hook without preserving its
  behavior. Protect newly created repositories through a repeatable
  reconciliation path.
- Canary a synthetic secret push and verify rejection before fleet rollout;
  verify a clean push and a complete post-rollout inventory. Record command,
  count, exceptions, and outcome without recording candidate values.
- Run a recurring hook reconciliation and verify its first execution. A Git
  template guard rejects a new repository's content push until the canonical
  hook is installed; verify both sides of this lifecycle before fleet rollout.

## Phase 4 — Scanner hardening and fleet redeployment

First-push decision: [ADR 0002](docs/adr/0002-first-push-gate.md).

The 0.2.1 review found two verified failures: a Git added line that looks like
`+++ /dev/null` can hide later findings in that patch, and a matched value in a
filename appears in redacted finding output. A byte limit can also turn an
unscanned input into a clean exit. Fix these contracts before publishing a new
binary. Keep the narrow fast detector and the pinned Gitleaks backstop.

| Order | Bead | Outcome |
|---:|---|---|
| 1 | `fss-9e40f126` | Parse Git headers and hunks without confusing added content for metadata; reject malformed patches. |
| 2 | `fss-c62fb72c` | Remove matched values from paths and every finding consumer. |
| 3 | `fss-8ddb10b1` | Distinguish complete clean scans from skipped or oversized input. |
| 4 | `fss-6b0c0b23` | Protect the first content push to a new Forgejo repository. |
| 5 | `fss-cd2fa510` | Triage the 23 measured generic misses and admit only high-signal improvements. |
| 6 | `fss-8ab567fa` | Verify immediate redacted scanning after file-write tool operations. |
| 7 | `fss-b490c817` | Validate, publish, and redeploy the combined release across the fleet. |

### Acceptance

- A real Git patch with a header-like added line followed by a synthetic
  candidate is rejected in staged, worktree, and server patch modes. Malformed
  patch input never exits clean.
- Finding output and agent feedback never contain a matched value, even when it
  also appears in a filename or standard-input path label.
- The scoped `fss-2272b3b4` detector correction also preserves that invariant
  for curl passwords encoded in valid JSON when the path label contains their
  semantic form. Runtime tests cover raw, quoted and object inputs; no real
  credential cleanup or broad hook rollout is admitted by this correction.
- Oversized or truncated text input fails closed. Unsupported binary input has
  a distinct status and proceeds to the pinned Gitleaks gate. Bounded input
  preserves the latency goal.
- New repositories receive the authoritative gate before their first content
  ref is accepted. The recurring reconciler continues to audit later drift.
- Codex and Claude file-write operations trigger the worktree scan immediately
  after the write; representative event and live runtime checks prove the hook
  actually runs. Hook feedback contains only redacted locations and rule IDs.
- Measured useful recall improves only if false positives and staged latency
  stay within the product objective. Document any retained coverage boundary.
- Complete Rust, hook, GitOps, and live canary checks precede a pinned binary
  release and full `jedarden/*` hook audit. Record commands, outcomes, target
  ArgoCD Application, deployment commits, and exceptions on the owning beads.
