#!/usr/bin/env bash
# Exercise the deployed hook bytes through bare Git's pre-receive transaction.
set -euo pipefail
umask 077
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

source_root=${DECLARATIVE_CONFIG_DIR:-"$HOME/declarative-config"}
source_hook="$source_root/tools/forgejo-secret-scan/pre-receive"
scanner_bin=${FASTSCAN_BIN:-/build/fast-secret-scanner/release/secret-scanner}
[[ -f "$source_hook" && -x "$scanner_bin" ]] || {
    echo 'Canonical hook or built secret-scanner is unavailable' >&2
    exit 2
}

test_root=$(mktemp -d "${TMPDIR:-$PWD}/forgejo-pre-receive-test.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/tmp" "$test_root/repositories/jedarden"
export TMPDIR="$test_root/tmp"
server="$test_root/repositories/jedarden/integration.git"
work="$test_root/work"
markers="$test_root/hook-markers"
gitleaks_calls="$test_root/gitleaks-calls"
config="$test_root/gitleaks.toml"
git init --quiet --bare "$server"
git init --quiet -b main "$work"
git -C "$work" config user.name 'Forgejo Integration Test'
git -C "$work" config user.email 'forgejo-test@example.invalid'
git -C "$work" remote add origin "$server"

# Seed an accepted commit before installing the guard. A new clean descendant
# must not cause the old candidate to be scanned again.
legacy_candidate="ghp_$(printf '%s%s%s%s' 'A7bQ9xL2' 'mN4pR8sT' '3vW6yZ1c' 'D5fG0hJk')"
printf 'legacy_key = %s\n' "$legacy_candidate" > "$work/legacy.txt"
git -C "$work" add legacy.txt
git -C "$work" commit --quiet -m 'accepted history predating the hook'
git -C "$work" push --quiet origin main
accepted=$(git --git-dir="$server" rev-parse refs/heads/main)

mkdir -p "$server/hooks/pre-receive.d"
cp "$source_hook" "$server/hooks/pre-receive.d/pre-receive"
chmod 755 "$server/hooks/pre-receive.d/pre-receive"
cmp -s "$source_hook" "$server/hooks/pre-receive.d/pre-receive"

# Model Forgejo's dispatcher: each executable receives the same ref updates,
# and any failure vetoes the transaction. The two sibling hooks are spies.
cat > "$server/hooks/pre-receive" <<'DISPATCH'
#!/bin/sh
updates=$(cat) || exit 1
status=0
for hook in "${GIT_DIR:-.}"/hooks/pre-receive.d/*; do
    [ -f "$hook" ] && [ -x "$hook" ] || continue
    printf '%s\n' "$updates" | "$hook" || status=1
done
exit "$status"
DISPATCH
cat > "$server/hooks/pre-receive.d/gitea" <<'GITEA'
#!/bin/sh
cat > /dev/null
printf 'gitea\n' >> "$HOOK_MARKERS"
exit "${GITEA_STATUS:-0}"
GITEA
cat > "$server/hooks/pre-receive.d/custom" <<'CUSTOM'
#!/bin/sh
cat > /dev/null
printf 'custom\n' >> "$HOOK_MARKERS"
exit "${CUSTOM_STATUS:-0}"
CUSTOM
chmod 755 "$server/hooks/pre-receive" "$server/hooks/pre-receive.d/gitea" \
    "$server/hooks/pre-receive.d/custom"

cat > "$config" <<'CONFIG'
title = "Forgejo integration test"
[extend]
useDefault = true
CONFIG

# A controlled Gitleaks double verifies the pinned invocation and lets the
# test exercise failure paths without relying on an installed Gitleaks version.
cat > "$test_root/gitleaks" <<'GITLEAKS'
#!/bin/sh
[ "$1" = git ] || exit 9
shift
redact=0
depth=0
range=0
policy=0
for arg in "$@"; do
    case "$arg" in
        --redact=100) redact=1 ;;
        --max-decode-depth=2) depth=1 ;;
        --log-opts=*' --not --all') range=1 ;;
        --config) policy=1 ;;
    esac
done
[ "$redact$depth$range$policy" = 1111 ] || exit 9
printf 'call\n' >> "$GITLEAKS_CALLS"
case "${GITLEAKS_MODE:-clean}" in
    clean) exit 0 ;;
    error) exit 2 ;;
    slow) sleep 2; exit 0 ;;
    *) exit 9 ;;
esac
GITLEAKS
cat > "$test_root/fast-error" <<'FAST_ERROR'
#!/bin/sh
exit 2
FAST_ERROR
cat > "$test_root/fast-slow" <<'FAST_SLOW'
#!/bin/sh
sleep 2
exit 0
FAST_SLOW
chmod 755 "$test_root/gitleaks" "$test_root/fast-error" "$test_root/fast-slow"

commit_clean() {
    printf '%s\n' "$1" > "$work/clean.txt"
    git -C "$work" add clean.txt
    git -C "$work" commit --quiet -m "$1"
}

assert_ref() {
    [[ "$(git --git-dir="$server" rev-parse refs/heads/main)" == "$accepted" ]] || {
        echo 'Rejected push changed the accepted ref' >&2
        exit 1
    }
}

push_expect() {
    local expected=$1 label=$2 diagnostic=$3
    shift 3
    local status=0
    : > "$markers"
    env FASTSCAN_BIN="$scanner_bin" GITLEAKS_BIN="$test_root/gitleaks" \
        GITLEAKS_CONFIG="$config" GITLEAKS_CALLS="$gitleaks_calls" \
        HOOK_MARKERS="$markers" SECRET_SCAN_ENABLED=1 \
        MAINTENANCE_REPOSITORIES_ROOT="$test_root/repositories" \
        MAINTENANCE_DIR="$test_root/maintenance" "$@" \
        git -C "$work" push --quiet origin main \
        > "$test_root/push.stdout" 2> "$test_root/push.stderr" || status=$?
    if [[ "$expected" == accept ]]; then
        [[ "$status" -eq 0 ]] || { echo "Unexpected rejection: $label" >&2; exit 1; }
        accepted=$(git --git-dir="$server" rev-parse refs/heads/main)
    else
        [[ "$status" -ne 0 ]] || { echo "Unexpected acceptance: $label" >&2; exit 1; }
        assert_ref
        if [[ -n "$diagnostic" ]]; then
            grep -Fq "$diagnostic" "$test_root/push.stderr" || {
                echo "Rejection did not identify expected cause: $label" >&2
                exit 1
            }
        fi
    fi
    assert_composed
    printf 'PASS: %s\n' "$label"
}

calls() { [[ -f "$gitleaks_calls" ]] && wc -l < "$gitleaks_calls" || printf '0\n'; }
assert_composed() {
    grep -qx gitea "$markers" && grep -qx custom "$markers" || {
        echo 'Forgejo or custom sibling hook did not run' >&2
        exit 1
    }
}

commit_clean 'clean novel descendant'
push_expect accept 'clean novel descendant' ''
[[ "$(calls)" -eq 1 ]]

blocked_candidate="ghp_$(printf '%s%s%s%s' 'Q7mN2vR9' 'pL4kS8tW' '5xY1cD3f' 'G6hJ0bV2')"
printf 'new_key = %s\n' "$blocked_candidate" > "$work/blocked.txt"
git -C "$work" add blocked.txt
git -C "$work" commit --quiet -m 'blocked synthetic candidate'
push_expect reject 'new synthetic candidate is blocked' 'fast Rust scanner found a candidate'
! grep -Fq "$blocked_candidate" "$test_root/push.stdout" "$test_root/push.stderr" || {
    echo 'Rejected push disclosed a candidate' >&2
    exit 1
}
[[ "$(calls)" -eq 1 ]] || { echo 'Gitleaks ran after Rust rejected a candidate' >&2; exit 1; }
git -C "$work" reset --hard --quiet "$accepted"

commit_clean 'clean push for failure cases'
push_expect reject 'missing Rust scanner fails closed' 'pinned Rust scanner binary is unavailable' \
    FASTSCAN_BIN="$test_root/missing-scanner"
push_expect reject 'missing Gitleaks fails closed' 'pinned Gitleaks binary or server policy is unavailable' \
    GITLEAKS_BIN="$test_root/missing-gitleaks"
push_expect reject 'Rust scanner error fails closed' 'fast Rust scanner exited with status 2' \
    FASTSCAN_BIN="$test_root/fast-error"
push_expect reject 'Rust scanner timeout fails closed' 'fast Rust scan exceeded 1s' \
    FASTSCAN_BIN="$test_root/fast-slow" FASTSCAN_TIMEOUT_SECONDS=1
push_expect reject 'Gitleaks error fails closed' 'Gitleaks exited with status 2' GITLEAKS_MODE=error
push_expect reject 'Gitleaks timeout fails closed' 'security scan timed out' \
    GITLEAKS_MODE=slow SCAN_TIMEOUT_SECONDS=1

push_expect reject 'custom sibling hook vetoes the push' '' CUSTOM_STATUS=1
push_expect reject 'Forgejo gitea hook vetoes the push' '' GITEA_STATUS=1
push_expect accept 'clean push after failures' ''
[[ "$(calls)" -eq 6 ]] || { echo 'Unexpected Gitleaks invocation count' >&2; exit 1; }
echo 'PASS: canonical pre-receive hook, novel-commit scope, fail-closed behavior, and hook composition'
