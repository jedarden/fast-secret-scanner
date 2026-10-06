# Independent curl qualification review — rejected first inputs

Reviewer: `/root/secret_release_review`, distinct from the implementation author.
Outcome owner: `fss-2272b3b4`; consuming release owner: `beadrs-b3059276`.
Reviewed on 2026-10-06; no installation, live-store mutation, credential access,
hook activation, commit, or push was performed by this reviewer.

## Frozen inputs

These SHA-256 values matched before and after source inspection and verification:

| Path | SHA-256 |
|---|---|
| `Cargo.toml` | `e87da399c0cf40862a0f64e18e4133bbf0827a983fcf6ac637b6313ce0309acd` |
| `Cargo.lock` | `946879666a5ccd343c33a50d676dc8945540b1cfc89b83c1e03a0f542ebd385b` |
| `src/detector.rs` | `bbf85e25197c3352ef7c0bff33c591e69d70207385facf9b620cf20be09d328d` |
| `tests/cli.rs` | `259811c41d0f7e988b72b25020ba0bc6047e8fa114cabc5cdd7a58c2431de196` |
| `research/rule-coverage.md` | `c2ec604530ea2ec182ff9262f0eb042dde1d10e1e0e722ad7be67c83a0892d9c` |
| `plan.md` | `f70ba31c368086da474911ae023a724ea59b5e1592f4655925303bc184ce8af9` |

## Decision

**Rejected: opaque credential positives are lost through the new identifier
exclusion.** The password-only entropy calculation correctly removes the
username-induced short/prose false positive, but applying the existing
`is_identifier_shaped` helper introduces a separate false-negative class.

That helper treats separator-joined, alphabetic-only components as identifiers
without measuring alphabetic case changes or long opaque material. Thus a
strongly alternating mixed-case alphabetic password with a hyphen is discarded,
as is a long alphabetic password with a Base64 separator. Both satisfy the new
password length, token-like, and entropy gates. Runtime-constructed independent
controls each yielded one `curl-auth-user` finding and exit 1 using the installed
0.2.7 scanner, but zero findings and exit 0 using these proposed 0.2.8 inputs.
The regression reproduced for both `-u` and `--user`, ordinary and high-entropy
usernames, and raw and JSON text.

The 88-control independent matrix passed 72 controls and failed the 16 variants
of these two classes. No candidate values were emitted: only case identifiers,
counts, statuses, exact-span predicates, and value-free-output predicates.

Required correction: use a curl-specific identifier exclusion that cannot
discard otherwise qualifying strong mixed-case or Base64-like opaque positives;
add permanent positive controls covering separator-bearing material and rerun
the full matrix. If long single-case separator-bearing material is intentionally
excluded, document that loss explicitly and obtain acceptance for that changed
boundary instead of claiming the positive class is preserved. Do not fix this
by restoring username entropy, blanket suppression, or weakening parity gates.

## Checks and confirmed properties

- `cargo fmt --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo test`: passed locally through the host wrapper, CPU quota 200%, memory
  maximum 6 GiB; 18 detector/Git unit tests, 11 CLI integration tests, two agent
  hook integration tests, one Git hook integration test, no failures or ignored
  tests. The binary target and doc tests contained zero tests.
- `cargo build --release`: passed, output under `/build/fast-secret-scanner`.
- `BENCH_TMP_ROOT=/home/coding/scratch ./scripts/benchmark.sh`: passed all
  expected exit-status controls, 21 runs per case, one-line/224-byte staged
  patch: Git diff median 4 ms, scanner median 6 ms, Gitleaks 8.25.1 median
  295 ms. This is one loaded-host observation, not a universal performance claim.
- Independently executed 88 runtime-constructed CLI controls and an installed
  0.2.7 comparison for the two failing classes; values traveled only through
  subprocess standard input. Reports contained no matched bytes.
- Proposed optimized scanner SHA-256:
  `5c084ed0bc6731b1daefca236e9e04413035cb6aa70d5652a6605771f495a4ac`.

Password-only short/prose/placeholder negatives passed with both usernames.
The exercised digit-bearing, alternating-case without separators,
symbol-bearing, and long alphabetic without separators positives retained
exact password-only spans, and stdout/stderr remained value-free. Existing
multiline curl and framed service tests passed. The scoped diff contains no
hook installer or server configuration change.

This review does not disposition existing application findings, approve actual
credential scrubbing, clear quarantine, approve a native bead-rs contract,
prove fleet replay coverage, or authorize publication. New corrected inputs
require another frozen-input review.
