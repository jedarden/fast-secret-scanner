#!/usr/bin/env bash
# Secret-safe staged benchmark against Gitleaks. Output contains only metadata
# and timings; detector output is discarded.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
runs=${RUNS:-21}
fixture_lines=${FIXTURE_LINES:-5000}
added_lines=${ADDED_LINES:-1}
scratch_root=${BENCH_TMP_ROOT:-${TMPDIR:-/tmp}}
gitleaks_bin=${GITLEAKS_BIN:-gitleaks}
target_directory=$(cargo metadata --no-deps --format-version=1 \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
scanner="$target_directory/release/secret-scanner"

cargo build --release --quiet
gitleaks_bin=$(command -v "$gitleaks_bin")
temporary=$(mktemp -d "$scratch_root/secret-scanner-bench.XXXXXX")
trap 'find "$temporary" -depth -delete' EXIT

git -C "$temporary" init -q
mkdir "$temporary/hooks"
git -C "$temporary" config core.hooksPath hooks
git -C "$temporary" config user.name scanner-benchmark
git -C "$temporary" config user.email scanner-benchmark@example.invalid

awk -v count="$fixture_lines" 'BEGIN {
  for (line = 1; line <= count; line++) {
    printf "ordinary configuration line %d = enabled\n", line
  }
}' > "$temporary/fixture.txt"
git -C "$temporary" add fixture.txt
git -C "$temporary" commit -q -m baseline

if ((added_lines > 1)); then
  awk -v count="$((added_lines - 1))" 'BEGIN {
    for (line = 1; line <= count; line++) {
      printf "new ordinary line %d = enabled\n", line
    }
  }' >> "$temporary/fixture.txt"
fi

synthetic_a='A7bQ9xL2mN4pR8sT'
synthetic_b='3vW6yZ1cD5fG0hJk'
printf 'service_api_token = "%s%s"\n' "$synthetic_a" "$synthetic_b" \
  >> "$temporary/fixture.txt"
git -C "$temporary" add fixture.txt

run_git_only() {
  git -C "$temporary" diff --cached --unified=0 --no-ext-diff -- >/dev/null
}

run_secret_scanner() {
  (cd "$temporary" && "$scanner" --quiet >/dev/null 2>&1)
}

run_gitleaks() {
  "$gitleaks_bin" git "$temporary" --staged --pre-commit --max-decode-depth=0 \
    --redact=100 --no-banner --log-level=error >/dev/null 2>&1
}

benchmark() {
  local label=$1
  local expected_status=$2
  local command=$3
  local -a samples=()
  local start_ns end_ns elapsed_ms status

  set +e
  "$command"
  status=$?
  set -e
  if [[ $status -ne $expected_status ]]; then
    printf '%s returned %d; expected %d\n' "$label" "$status" "$expected_status" >&2
    exit 1
  fi

  for ((iteration = 0; iteration < runs; iteration++)); do
    start_ns=$(date +%s%N)
    set +e
    "$command"
    status=$?
    set -e
    end_ns=$(date +%s%N)
    if [[ $status -ne $expected_status ]]; then
      printf '%s returned %d; expected %d\n' "$label" "$status" "$expected_status" >&2
      exit 1
    fi
    elapsed_ms=$(((end_ns - start_ns) / 1000000))
    samples+=("$elapsed_ms")
  done

  printf '%s\n' "${samples[@]}" | sort -n > "$temporary/$label.samples"
  local minimum maximum median mean
  minimum=$(head -n 1 "$temporary/$label.samples")
  maximum=$(tail -n 1 "$temporary/$label.samples")
  median=$(awk '{value[NR]=$1} END {
    if (NR % 2) print value[(NR+1)/2]
    else print int((value[NR/2]+value[NR/2+1])/2)
  }' "$temporary/$label.samples")
  mean=$(awk '{sum+=$1} END {printf "%.1f", sum/NR}' "$temporary/$label.samples")
  printf '%s\t%d\t%s\t%s\t%s\t%s\n' \
    "$label" "$runs" "$median" "$mean" "$minimum" "$maximum"
}

printf '# date_utc=%s\n' "$(date -u +%FT%TZ)"
printf '# scanner_version=%s\n' "$($scanner --version)"
printf '# scanner_sha256=%s\n' "$(sha256sum "$scanner" | awk '{print $1}')"
printf '# gitleaks_version=%s\n' "$($gitleaks_bin version | tail -n 1)"
printf '# fixture_lines=%s\n' "$fixture_lines"
printf '# added_lines=%s\n' "$added_lines"
printf '# staged_patch_bytes=%s\n' \
  "$(git -C "$temporary" diff --cached --unified=0 --no-ext-diff -- | wc -c)"
printf '# load_average=%s\n' "$(cut -d' ' -f1-3 /proc/loadavg)"
printf 'case\truns\tmedian_ms\tmean_ms\tmin_ms\tmax_ms\n'

benchmark git_diff 0 run_git_only
benchmark secret_scanner 1 run_secret_scanner
benchmark gitleaks_staged_decode0 1 run_gitleaks
