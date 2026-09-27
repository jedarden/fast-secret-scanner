# Gitleaks performance research

Research date: 2026-09-27

Gitleaks is already efficient for a comprehensive scanner. It extracts Git
patches, uses an Aho-Corasick keyword prefilter, evaluates Go/RE2-compatible
regular expressions, applies entropy thresholds and allowlists, and optionally
recursively decodes encoded content. Its broader semantics impose startup and
rule-engine work that a narrow staged tripwire can avoid.

## Measured baseline

On the private source research repository, the official Gitleaks 8.30.1 release
scanned a 144.39 MB full-history payload in 3.34 seconds with decoding disabled.
Default recursive decoding increased the run to 7.45 seconds. Installed
Gitleaks 8.25.1 took 4.82 seconds on the same decode-disabled scan.

A plain local Gitleaks build was substantially slower because official release
artifacts use the `gore2regex` build tag and `wasilibs/go-re2`. This supports
pinning the official binary rather than casually rebuilding it.

The largest safe optimization remains scan-surface selection:

1. staged additions for immediate developer feedback;
2. exact pushed commit ranges for the authoritative gate;
3. full history only for onboarding, rule changes, and upgrades.

## Why this scanner can win staged latency

`secret-scanner` has no general configuration parser, runtime regex compiler,
decoding loop, archive support, history traversal, or 200-plus-rule catalog. It
launches Git once and evaluates a deliberately small set of byte-oriented
rules. The comparison is therefore useful only for feedback latency, not total
security coverage.

## Benchmark discipline

- Use the same staged patch for both scanners.
- Warm once and report medians and tails across repeated runs.
- Record binary versions, fixture size, patch bytes, and system load.
- Discard scanner output so a benchmark cannot copy a candidate into logs.
- Require both tools to return their finding status; a fast scanner that failed
  to detect the fixture is not a valid sample.
- Keep generated candidates synthetic and construct them from fragments.

Primary references:

- <https://github.com/gitleaks/gitleaks>
- <https://github.com/gitleaks/gitleaks/blob/v8.30.1/detect/detect.go>
- <https://github.com/gitleaks/gitleaks/blob/v8.30.1/sources/git.go>
- <https://github.com/gitleaks/gitleaks/blob/v8.30.1/.goreleaser.yml>
