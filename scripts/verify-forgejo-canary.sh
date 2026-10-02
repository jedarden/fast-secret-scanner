#!/usr/bin/env bash
# Exercise a live Forgejo pre-receive hook with a clean and synthetic-secret push.
set -euo pipefail
umask 077

repo="${1:-jedarden/fast-secret-scanner}"
[[ "$repo" == jedarden/* ]] || { echo 'Expected a jedarden/REPO argument' >&2; exit 2; }
source_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

scratch="$(mktemp -d /home/coding/scratch/fastscan-canary.XXXXXX)"
branch="fastscan-canary-$(date -u +%Y%m%d%H%M%S)-$$"
remote="https://git.ardenone.com/$repo.git"
cleanup() {
    local status=$? ref attempt removed=0
    trap - EXIT
    if [[ "${clean_pushed:-0}" -eq 1 ]]; then
        for attempt in 1 2 3; do
            if git -C "$scratch/repo" push -q origin ":refs/heads/$branch" >/dev/null 2>&1; then
                ref="$(git -C "$scratch/repo" ls-remote origin "refs/heads/$branch" 2>/dev/null || true)"
                if [[ -z "$ref" ]]; then
                    removed=1
                    break
                fi
            fi
            sleep 2
        done
        if [[ "$removed" -ne 1 ]]; then
            echo "Canary branch cleanup failed: $branch" >&2
            status=1
        fi
    fi
    rm -rf -- "$scratch"
    exit "$status"
}
trap cleanup EXIT

git clone -q --local --no-hardlinks "$source_repo" "$scratch/repo"
git -C "$scratch/repo" remote set-url origin "$remote"
git -C "$scratch/repo" -c core.hooksPath=/dev/null checkout -q -b "$branch" origin/main
git -C "$scratch/repo" config user.name scanner-canary
git -C "$scratch/repo" config user.email scanner-canary@example.invalid
git -C "$scratch/repo" config core.hooksPath /dev/null

git -C "$scratch/repo" commit -q --allow-empty -m 'Verify clean Forgejo scan' --
git -C "$scratch/repo" push -q origin "HEAD:refs/heads/$branch"
clean_pushed=1
clean_head="$(git -C "$scratch/repo" rev-parse HEAD)"
echo 'Clean novel commit: accepted'

# Runtime fragments keep a complete provider-shaped test token out of source.
prefix='ghp_'
fragment='A7bQ9xL2'
candidate="${prefix}${fragment}${fragment}${fragment}${fragment}${fragment}"
printf 'synthetic_canary = %s\n' "$candidate" > "$scratch/repo/canary-fixture.txt"
git -C "$scratch/repo" add -- canary-fixture.txt
git -C "$scratch/repo" commit -q -m 'Verify synthetic secret rejection' -- canary-fixture.txt

if git -C "$scratch/repo" push -q origin "HEAD:refs/heads/$branch" \
    > "$scratch/push.stdout" 2> "$scratch/push.stderr"; then
    echo 'Synthetic provider-shaped candidate was accepted unexpectedly' >&2
    exit 1
fi
if ! grep -q 'possible secret detected' "$scratch/push.stderr"; then
    echo 'Push was rejected, but not by the Rust secret detector' >&2
    exit 1
fi
if grep -Fq "$candidate" "$scratch/push.stdout" "$scratch/push.stderr"; then
    echo 'Rejected push exposed the candidate value' >&2
    exit 1
fi
remote_head="$(git -C "$scratch/repo" ls-remote origin "refs/heads/$branch" | cut -f1)"
[[ "$remote_head" == "$clean_head" ]] || {
    echo 'Rejected push changed the remote canary ref' >&2
    exit 1
}
echo 'Synthetic provider-shaped candidate: rejected without value disclosure'
echo 'Rejected ref: unchanged'
