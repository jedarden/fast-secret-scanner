# Scoped curl/JSON implementation exact-input review — accepted

Independent reviewer: `/root/secret_release_review`, distinct from `/root`,
author of the implementation, tests and documentation. Outcome owner:
`fss-2272b3b4`; consuming application outcome: `beadrs-b3059276`.
Reviewed on 2026-10-06. Original round-1 and round-2 rejection evidence remains
unchanged; this decision accepts only the corrected inputs below.

## Exact accepted inputs

All SHA-256 hashes matched before and after independent verification:

| Path | SHA-256 |
|---|---|
| `Cargo.toml` | `98ec8b29ebfa532332071405d4857a042ba512f452a4749e3c1515f5e4e4dce5` |
| `Cargo.lock` | `e679d5f41e55f4ef48a28daa9e9511c8f8830938047017628ee38bec503ec4eb` |
| `README.md` | `cd9143a2d3d81d1b6208c8598335b84e95d53b789e90ed93fd8648cf03f5628e` |
| `src/detector.rs` | `d23a7d530c438dbfb4ec5ff5805023e1eb54e36a1cd1ad30ffda0ed6b147e52a` |
| `tests/cli.rs` | `4f66bd2f707dbe88959666da54734a5b0eb5fad24fc390445ff1f8444f8f7d01` |
| `research/rule-coverage.md` | `c59b91bc57b1573a0a9bbf582808129813170eb659696ff81c08da2f1779bbb6` |
| `notes/design.md` | `99b83403dd1e706de5a1249dd5bb25bb78e3be50d20da3a0ab020a78cad8f6eb` |
| `plan.md` | `d1aef09af2a439fbbbf2eceadf04b689edae57f8d47128cc5bdd8cc6911bf17b` |

**Accepted: no actionable defect remains in the scoped password-only
qualification, validated JSON capture/mapping and decoded-label safety
correction.** This is not application release/fleet acceptance or a claim of
complete arbitrary/encoded credential detection.

## Findings resolved

- Username entropy cannot qualify a missing, short or ordinary prose password.
  Length/entropy and token-shape evidence come from password bytes alone.
- The first correction's opaque alphabetic separator regression is fixed.
  Strong alternating-case, Base64-like and long alphabetic positives remain
  covered. Intentionally retained long words/identifiers are documented as
  possible credentials rather than asserted clean.
- JSON interpretation requires complete document validation using
  `serde::de::IgnoredAny` and `Deserializer::end`, not a prefix/quote guess.
  Invalid, truncated, trailing-data, or excessive-depth JSON keeps ordinary raw
  scanning; rejected JSON is not converted into a clean result.
- The bounded decoder handles UTF-8 and JSON escapes, including surrogate pairs,
  mapping every semantic byte to the complete encoded character/escape that
  produced it. Qualification uses semantic password bytes; findings borrow
  only the original encoded input range. Actual escaped LF/CR/tab terminate the
  password and cannot supply length/entropy. Literal backslashes remain material.
- A further independent preacceptance probe found an inherited plaintext-label
  exposure when a detected password was represented through JSON Unicode
  escapes. The final correction checks a bounded decoded alias only for an
  already detected curl password, retaining only the unsafe-path flag.
  Plaintext and directly matching encoded labels redact; safe ordinary labels
  remain intact. Conservative alias hiding of raw backslash literals changes
  no finding or span and cannot suppress detection.
- Coverage/design/plan state the complete-JSON and 256-source-byte capture
  limitations and raw fallback. README no longer incorrectly claims a
  dependency-free binary after adding the necessary Serde dependencies.

There is no hook installer/server activation change, actual credential cleanup,
quarantine reset, protocol redesign, or saved-report import in this patch.

## Independently executed verification

Checks ran locally with build output under `/build/fast-secret-scanner`.
The stable complete-test command reported the host wrapper's CPU quota 200%
and memory maximum 6 GiB. No remote verification is claimed.

- `cargo fmt --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo test`: all 34 passed, zero failed/ignored: 18 unit, two agent-hook,
  13 CLI and one Git-hook tests; binary/doc targets have zero tests.
- `cargo build --release`: passed. Independently verified optimized binary:
  `cd7c7c0d845c48c560314c1c31df1a0609e6b3dc88ea83364c76b978a4ad68f0`.
- `cargo +1.85 test --locked`: all 34 passed, zero failed/ignored, including
  the new dependencies and semantic-label test; MSRV compatibility verified.
- Independently reran a 1,558-document framed-service matrix on that exact
  optimized binary. All 1,558 produced exact expected findings/encoded spans
  and value-free stdout/stderr: raw/fullquoted/object/array input, UTF-8 and
  ASCII escaping, actual LF/CR/tab, literal backslashes one through eight
  followed by `n`, `r`, `t` or `u0041`, ordinary/high-entropy usernames,
  malformed/trailing/deep JSON and invalid-surrogate fallback controls.
- Independently ran 36 label controls covering escaped ASCII/Unicode,
  backslash passwords, raw/quoted/object/all-escaped input, semantic/directly
  matching encoded labels and safe ordinary labels. All relevant redaction,
  value-free output and safe-label-preservation predicates passed. The inherited
  semantic-label reproduction now redacts instead of exposing plaintext.
- `BENCH_TMP_ROOT=/home/coding/scratch ./scripts/benchmark.sh`: passed all
  expected exits, 21 runs/case, one-line/224-byte staged patch; medians Git
  5 ms, scanner 6 ms, Gitleaks 8.25.1 330 ms. This loaded-host observation is
  not a universal latency claim or a hostile-JSON benchmark.
- `git diff --check` on the eight exact scoped inputs: passed.
- Final SHA-256 recomputation confirmed every accepted input unchanged.

Tests construct invented values at runtime and send them through subprocess
stdin; reports include only case labels, counts, byte lengths and predicates.
No real values or stores were inspected. The reviewer changed only review
evidence, not the implementation, tests, docs, plan, live bead, installed binary,
hook or managed resource; no commit or push was performed.

Actual bead-rs optimized-artifact parity, full reachable-fleet replay and
fingerprint dispositions, advisory reduction, hostile-field cost, host
installation verification and publication/deployment gates remain required.
This review does not authorize real scrubbing or manual quarantine clearing.
