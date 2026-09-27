# Secret Scanner contributor guide

This repository optimizes for very fast feedback on staged Git additions. It
is intentionally a high-value-pattern tripwire rather than a Gitleaks
replacement.

## Repository map

- `src/detector.rs`: byte-oriented rules and detector unit tests.
- `src/git.rs`: staged-patch acquisition and parsing.
- `src/main.rs`: CLI arguments, scan modes, output, and exit codes.
- `tests/cli.rs`: process-level behavior and redaction checks.
- `research/`: benchmark data, coverage evidence, and rule boundaries.
- `notes/`: objective and architecture decisions.
- `scripts/benchmark.sh`: repeatable staged-scan comparison with Gitleaks.

Read `README.md` for the user contract, `notes/design.md` before changing the
data path, and `research/rule-coverage.md` before changing a detector.

## Safety invariants

- Never print, log, snapshot, or commit matched values. Findings contain only
  path, line number, and rule ID.
- Tests and benchmarks must construct synthetic candidates at runtime from
  fragments. Never add a live credential or a complete provider-shaped token
  to a tracked fixture.
- Keep the default scan surface to staged additions. Any broader mode must be
  explicit.
- Coverage may be narrower than Gitleaks, but changes must not silently remove
  an existing rule. Update `research/rule-coverage.md` when coverage changes.

## Verification

Run from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
./scripts/benchmark.sh
```

Cargo output must remain in `/build/secret-scanner`, as enforced by the host
wrapper. Benchmark output containing machine-specific load data belongs under
`research/` only when intentionally recorded.

For documentation-only changes, `git diff --check` and both repository scanners
are sufficient. For Rust changes, run formatting, Clippy, and the complete test
suite. Run the benchmark only when the detection path, Git path, build profile,
or performance claim changes.

## Change protocol

1. Keep additions scoped; do not turn the fast path into a Gitleaks clone.
2. Add positive, near-miss, placeholder, and redaction tests for rule changes.
3. Construct provider-shaped test values from fragments at runtime.
4. Update the coverage table and known gaps when behavior changes.
5. Benchmark end to end; detector-only microbenchmarks do not prove lower
   pre-commit latency.
