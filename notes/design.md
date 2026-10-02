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

## Detector strategy

Provider tokens are recognized by literal prefix, allowed suffix alphabet, and
length. Generic assignments require a credential-like identifier, a nearby
assignment operator, a bounded token, letters plus digits, Shannon entropy, and
placeholder rejection.

The implementation intentionally avoids a runtime regex compiler. With this
small rule set, bounded byte searches are easier to audit and minimize process
startup. If the rule count grows enough for repeated scans to dominate, the
next design should use an Aho-Corasick keyword pass before evaluating individual
rules.

## Redaction invariant

Detection functions return stable rule IDs only. They do not return match
ranges or candidate strings, which makes accidental secret logging harder.
CLI output escapes control characters in paths and prints no source line.

## Known parser boundary

The patch parser uses Git's normal textual patch format with `core.quotePath`
disabled. It supports ordinary paths, spaces, renames with content changes, and
new files. Filenames containing literal newlines are not a supported staged
surface. An authoritative Gitleaks gate compensates for this deliberate edge
case.
