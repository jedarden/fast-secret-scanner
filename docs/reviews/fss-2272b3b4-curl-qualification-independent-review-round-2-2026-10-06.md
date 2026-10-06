# Independent curl qualification review — round 2 requires revision

Reviewer: `/root/secret_release_review`, independent from the author.
Owner: `fss-2272b3b4`; consuming owner: `beadrs-b3059276`.

## Exact reviewed inputs

All SHA-256 values were recomputed before verification:

| Path | SHA-256 |
|---|---|
| `Cargo.toml` | `e87da399c0cf40862a0f64e18e4133bbf0827a983fcf6ac637b6313ce0309acd` |
| `Cargo.lock` | `946879666a5ccd343c33a50d676dc8945540b1cfc89b83c1e03a0f542ebd385b` |
| `src/detector.rs` | `c00255a7c95a82aaa6b229e2ac06c5720f10418de34142f7692affdcc7e3b236` |
| `tests/cli.rs` | `c22532dd68516ada2c812e391b0787e9f1de3ba178d554837335dbfadce95e61` |
| `research/rule-coverage.md` | `a3f6bc8cfa1ee419b689bbd667023386fdb46bd06787106090b15f297ce8d5dc` |
| `plan.md` | `f70ba31c368086da474911ae023a724ea59b5e1592f4655925303bc184ce8af9` |

## Decision and disposition of first rejection

**Requires revision before the claimed exact raw/JSON curl boundary is
accepted.** The first review's newly introduced opaque-identifier regression
is fixed: strong alternating-case separator-bearing material, long alphabetic
material, and `+`, `/`, `=` Base64-like positives remain covered. Short name
exclusion no longer silently discards those classes. Coverage now explicitly
retains long alphabetic words/identifiers as possible credentials rather than
claiming they are clean.

An additional independent framed-service control exposed a **pre-existing**
JSON-multiline boundary defect, present in installed 0.2.7 and still present
in these inputs. When a password ends a line and that document is JSON-escaped,
the literal escaped newline is consumed as password bytes. A five-letter
prose password is then treated as a seven-byte symbol-bearing credential.
Qualified positive spans also include the two escaped newline bytes after the
password. The test compares the span bytes to the exact planted password,
not a transformed or logged copy.

For both installed 0.2.7 and proposed 0.2.8, independently tested results were:

| Synthetic case | Expected password bytes | Reported span bytes | Findings |
|---|---:|---:|---:|
| Short prose at end of JSON-escaped line | 5 | 7 | 1 |
| Alternating-case hyphen positive | 9 | 11 | 1 |
| Digit-bearing positive | 6 | 8 | 1 |

This is not attributed to the new qualifier. Nevertheless, it prevents the
stated plan acceptance for short/prose negatives and exact password spans on
raw/JSON multiline curl inputs. Required correction: define and test escaped
whitespace capture boundaries without allowing formatting escapes to supply
password entropy/length evidence. Preserve opaque literal-backslash password
controls and document any deliberately unsupported ambiguity. Do not suppress
all curl findings or use username entropy to recover coverage.

## Actual verification

- `cargo fmt --check`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo test`: all 32 tests passed locally under CPU quota 200% and 6 GiB
  memory maximum: 18 unit, 11 CLI, two agent-hook and one Git-hook tests;
  zero failed/ignored. Binary/doc targets contain zero tests.
- `cargo build --release`: passed under `/build/fast-secret-scanner`.
- Optimized scanner SHA-256:
  `86455e740fa404bf9920ea36dccdbbcbefaa9e36d62bd097daed8efb90b16e7a`.
- Independently ran 288 single-line raw/JSON/UTF-8-prefixed CLI controls across
  three username shapes and two options. All passed exact span, value-free
  output, and expected finding/exit predicates.
- Independently ran 12 multiline raw/JSON documents through one `--serve`
  process: 12 responses, process exit 0, seven controls passed and five
  JSON-escaped multiline controls failed. Raw multiline controls passed.
- Independently compared three failing JSON multiline classes with installed
  0.2.7 to distinguish the inherited defect from a regression. No matched
  values were printed; reports contained only labels, counts and predicates.
- `BENCH_TMP_ROOT=/home/coding/scratch ./scripts/benchmark.sh`: passed, 21
  runs/case, one-line/224-byte staged patch, medians Git 4 ms, scanner 6 ms,
  Gitleaks 8.25.1 392 ms. One loaded-host observation only.

No real values or stores were inspected, and no source, tests, coverage,
plan, installation, hook configuration, live bead, commit or push was changed
by this reviewer. This does not disposition application findings, authorize
actual scrubbing, clear quarantine, or approve the application release.
