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
