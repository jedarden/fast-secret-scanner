# ADR 0002: Guard a repository's first content push

Status: Accepted for deployment, 2026-10-02

## Context

The canonical Forgejo pre-receive hook is installed per repository through the
admin API. A periodic reconciler can find repositories created since its last
run, but a push-to-create transaction can present content before reconciliation
has installed the hook. An empty repository created through the UI has the same
gap. The comprehensive Gitleaks pass must run before any new ref is accepted.

Forgejo 15.0.7 calls `git init --bare` when creating a repository, then writes
its generated `pre-receive` dispatcher and its own `pre-receive.d/gitea` hook.
The dispatcher invokes every executable file in `pre-receive.d`. Git's
`GIT_TEMPLATE_DIR` copies additional files into a new bare repository before
Forgejo writes the dispatcher. Forgejo preserves those additional files.

## Decision

Set `GIT_TEMPLATE_DIR` for the Forgejo container and install a small executable
`pre-receive.d/secret-scanner-required` in that template during pod startup.
The guard rejects content pushes until the repository has the recognizable
canonical `pre-receive.d/pre-receive` scan hook. The scheduled reconciler then
installs and verifies that hook through the admin API. Forgejo's dispatcher
runs the guard, its own hook, the canonical hook, and any custom hooks.

The template guard does not scan by itself. Once the canonical hook exists,
that hook runs the bounded Rust pass and the pinned, server-owned Gitleaks
policy before Git moves a ref. A missing scanner or scanner error still rejects
the push. Existing repositories continue to use their installed canonical
hooks and are covered by the fleet inventory and reconciliation.

## Consequences

A first push to a newly created repository may be rejected. For push-to-create,
the rejected attempt can leave an empty repository for the reconciler to find;
retry the push after the canonical hook is installed. This trades a short wait
for eliminating the unscanned first-push window. The guard is installed only
when a repository is initialized, so changing its logic later requires a
separate migration for existing repositories. Keep the canonical per-repository
hook and its hash audit; a template guard alone is insufficient.

The GitOps manifest owns the template and runtime configuration for the
`forgejo-iad-ci` ArgoCD Application in `iad-ci`. A local bare-Git integration
test extracts the exact guard bytes from that manifest, exercises first-push
rejection, a synthetic secret after hook installation, a clean push, and custom
hook composition. A live Forgejo canary must verify that the chart passes
`GIT_TEMPLATE_DIR` to the running container and that Forgejo's creation path
preserves the seeded hook before the fleet rollout is considered complete.
