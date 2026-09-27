# Objective

The primary objective is for `secret-scanner` to reject common accidental
credentials materially faster than Gitleaks on the staged-change path.

Initial status: met. The 2026-09-27 release benchmark was about 67x faster on a
one-line staged addition and 17x faster on a 169 KB addition. These ratios are
machine- and load-specific, but comfortably exceed the 3x acceptance boundary.

## Success criteria

1. Median staged-scan wall time is at least 3x faster than the locally installed
   Gitleaks release on the same generated fixture and host.
2. The default command scans only additions in the Git index.
3. It catches the provider prefixes and contextual patterns listed in
   `research/rule-coverage.md`.
4. It never prints or persists matched values.
5. Its false-negative boundary is documented honestly; it is never presented
   as a comprehensive Gitleaks replacement.

Inferior coverage is acceptable. Latency is not an excuse to weaken the
authoritative gate: Forgejo or CI should still scan the exact pushed commit
range with a pinned Gitleaks binary and configuration.

## Non-goals

- Complete compatibility with Gitleaks rules, baselines, fingerprints, and
  allowlists.
- Full-history, archive, binary, or recursive-decoding scans.
- Provider calls to determine whether a candidate is live.
- Printing matching text for developer convenience.
- Parallel scanning of tiny staged diffs, where scheduling overhead dominates.

## Decision rule

Keep the implementation dependency-free and single-threaded until benchmarks
show a specific bottleneck. A more sophisticated regex or multi-pattern engine
must earn its startup and maintenance cost with an end-to-end staged benchmark,
not a microbenchmark alone.
