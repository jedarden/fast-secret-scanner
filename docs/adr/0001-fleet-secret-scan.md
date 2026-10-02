# ADR 0001: Fleet deployment of the fast secret scanner

Status: accepted, 2026-09-28

## Context

The Rust scanner only reads staged additions today. A global local Git hook
currently runs Gitleaks, and four local repositories override that hook path.
The Forgejo pre-receive hook uses Gitleaks on novel commits. Agent edits and
pushes from other machines can bypass a workstation-only scanner.

## Decision

1. Keep `secret-scanner`'s default staged mode. Add explicit `--worktree`
   mode for agent feedback and `--patch-stdin` for server-side novel-commit
   patches. Both report only escaped path, line, and rule ID.
2. Install a checksum-verified, pinned static Linux release on Forgejo's data
   PVC through GitOps. The pre-receive hook pipes patches for novel commits
   into Rust before invoking its existing Gitleaks pass. Nonzero execution
   errors, missing runtime, and timeout reject the push.
3. Run Rust before Gitleaks in the fleet pre-commit dispatcher. Chain existing
   repository hooks. Explicitly integrate clones with a local `core.hooksPath`
   override, preserving their own hook behavior.
4. Install user-level Codex and Claude Code lifecycle hooks for early feedback.
   These provide remediation prompts, while the Git and Forgejo gates prevent
   a commit or pushed ref from containing a detected candidate.
5. Reconcile every `jedarden/*` Forgejo pre-receive hook and audit exact hook
   hashes. An always-on user timer reruns the authenticated reconciliation
   every 15 minutes for repositories created later.

## Consequences

The Rust detector is intentionally narrower than Gitleaks, so Gitleaks remains
the authoritative comprehensive server pass. Server coverage is the property
that holds across machines; agent hooks improve response time. A detected
candidate may already exist in a local uncommitted file, so remediation must
remove and rotate any live credential. The hook prints no candidate values.
Unrecognized repository-specific pre-receive hooks require composition rather
than replacement.

The timer cannot guard the initial push-to-create transaction: the repository
does not exist when the client begins that push. ADR 0002 adds a Git-template
guard at repository initialization. It rejects a first content push until the
canonical API-managed hook is installed. The timer remains responsible for
installing that hook and auditing later drift.
