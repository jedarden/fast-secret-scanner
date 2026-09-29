# Pinned Linux release artifact

`secret-scanner-v0.2.0-x86_64-unknown-linux-musl` is a static Linux binary
built from this repository's Rust source with:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Its SHA-256 is
`59f13c19a283b7bec20bcda93138a9d0c98cbc554b973855fc1e63381da55ae6`.
The Forgejo GitOps init script pins the containing source commit and checks
this digest before installation. Rebuild and repin both when source changes.
