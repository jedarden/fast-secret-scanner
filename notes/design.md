# Design notes

## Data path

```text
Git index
  -> one `git diff --cached --unified=0` process
  -> patch parser keeps `+` lines and new-file line numbers
  -> bounded byte-oriented detectors
  -> deduplicated path:line:rule findings
  -> exit 1 when any candidate exists
```

The scanner does not request complete staged blobs. That saves subprocesses and
prevents unchanged historical examples from blocking an unrelated commit.
Git rename detection is enabled for staged and worktree diffs: a renamed
content-addressed checkpoint object contributes only its changed lines, while
new records in that object and entirely new files remain scan inputs.
Patch parsing tracks file headers and hunk line counts. A `+++ ` byte sequence
inside an added line remains file content, so it cannot change the active path
or hide following additions. Inconsistent or truncated patch input returns an
execution error instead of a clean result.
Git diff output and patch standard input are capped at 512 MiB before parsing.
Oversized or binary file scans and Git binary patch markers increment skip
counts. Oversized input exits `2`; binary input without a text finding exits
`3`, so fleet hooks can continue to their pinned Gitleaks backstop. Both
statuses report counts without filenames. Exit `0` means every selected text
input was scanned without a finding.

## Detector strategy

Provider tokens are recognized by literal prefix, allowed suffix alphabet, and
length. Generic assignments require a credential-like identifier, a nearby
assignment operator, a bounded token, letters plus digits, Shannon entropy, and
placeholder rejection.

Curl password qualification is independent of the username. For a complete
valid JSON document, its bounded curl token window is decoded with a byte-range
map before measuring password evidence. `serde::de::IgnoredAny` validates the
document without retaining parsed values; it is not a prefix/quote guess.
Actual escaped LF/CR/tab delimit the semantic password, while paired escaped
backslashes remain password material. Findings still borrow only the exact
encoded input range. Ordinary raw curl input is unchanged. Invalid JSON, or
JSON beyond the parser's normal depth bound, keeps raw scanning and does not
gain a clean-scan exemption. Other detectors retain their existing byte-oriented
rules; this does not claim general recursive JSON decoding.

The implementation intentionally avoids a runtime regex compiler. With this
small rule set, bounded byte searches are easier to audit and minimize process
startup. If the rule count grows enough for repeated scans to dominate, the
next design should use an Aho-Corasick keyword pass before evaluating individual
rules.

## Redaction invariant

Detection functions return a stable rule ID and a borrowed slice of the
current source line. The slice is used only to decide whether an untrusted path
or input label must be replaced with `<redacted-path>`; it is never retained in
a finding, log, or report. Known provider shapes in a path also trigger the
replacement. CLI output escapes control characters in safe paths and prints
no source line.

For an already detected curl password containing JSON escapes, path safety
also checks its bounded decoded alias. Only the safety flag survives; findings
and span offsets remain encoded-source-relative. A raw backslash literal may
conservatively hide a possible decoded alias in the label without suppressing
any detection. Ordinary safe labels remain unchanged.

## Known parser boundary

The patch parser uses Git's normal textual patch format with `core.quotePath`
disabled. It supports ordinary paths, spaces, renames with content changes, and
new files. Filenames containing literal newlines are not a supported staged
surface. An authoritative Gitleaks gate compensates for this deliberate edge
case.
