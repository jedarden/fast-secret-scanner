# Pinned Linux release artifact

`secret-scanner-v0.2.1-x86_64-unknown-linux-musl` is a static Linux binary
built from this repository's Rust source with:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Its SHA-256 is
`4c4edfb640ec472106cef6d9128cce7d8da9bfd06df9f36f632727d5eb45b9e3`.
The Forgejo GitOps init script pins the containing source commit and checks
this digest before installation. Rebuild and repin both when source changes.
The prior `0.2.0` artifact is retained for rollback.

## 0.2.2 (agent-hook hosts)

`secret-scanner-v0.2.2-x86_64-unknown-linux-musl` is built the same way from
commit `3c5b885` (bead `fss-ea8be9a5`: `generic-api-key` no longer treats a
URL scheme colon or a prose comma as an assignment). Its SHA-256 is
`d366542c98a7bfb8b9173e2e760215b8bd80b45024b34c8d4a98dcc78a7c1bcd`.
It is installed as `~/.local/bin/secret-scanner` on codinghome. The Forgejo
GitOps init script still pins `0.2.1`; repin it there deliberately, with this
digest, when the server gate should pick the change up.

## 0.2.3 (scanner hardening and file-write hooks)

`secret-scanner-v0.2.3-x86_64-unknown-linux-musl` includes the staged-patch
parser fix, redacted path output, explicit incomplete-scan status, the
high-signal `_key` rule, and file-write hook support. It is built with the
same static target command. Its SHA-256 is
`7fbd15df571f29489ff733acb96aa7ac65d4ba957cc25d4ff71816c517a3a62d`.
The Forgejo GitOps pin must name the commit containing this artifact and this
digest; the server retains pinned Gitleaks as the comprehensive gate.
