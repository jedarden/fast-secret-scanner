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
It was installed as `~/.local/bin/secret-scanner` on codinghome. At that
release, the Forgejo GitOps init script remained pinned to `0.2.1`.

## 0.2.3 (scanner hardening and file-write hooks)

`secret-scanner-v0.2.3-x86_64-unknown-linux-musl` includes the staged-patch
parser fix, redacted path output, explicit incomplete-scan status, the
high-signal `_key` rule, and file-write hook support. It is built with the
same static target command. Its SHA-256 is
`7fbd15df571f29489ff733acb96aa7ac65d4ba957cc25d4ff71816c517a3a62d`.
The Forgejo GitOps pin names source commit
`555871ec0f77f6687379bab73dd80ecde72cb05f` and this digest in
`declarative-config` commit `382bb6c5aa03ac9147ddf8ba839321a78674b63e`.
The server retains pinned Gitleaks 8.30.1 as the comprehensive gate.

## 0.2.4 (false-positive narrowing, fss-eeeb789c)

`secret-scanner-v0.2.4-x86_64-unknown-linux-musl` is built with the same
static target command from commit
`49e5b894e97241d0aaa1475baaadec8f938693a2`. It stops flagging every
ExternalSecret / ClusterSecretStore / SealedSecret manifest, prose in bead
checkpoints, and template placeholders (845 findings to 3 on the measured
corpora; see `research/rule-coverage.md`). Its SHA-256 is
`8c649fc85eb8ca817ee45a1e9efa8e448eb746b4297dca4f6708d12d3e74c79e`.
It is installed as `~/.local/bin/secret-scanner` on codinghome. The Forgejo
GitOps init script still pins `0.2.3`; repin it with this source commit and
digest before turning content scanning back on in the pre-receive gate
(declarative-config `SECRET_SCAN_ENABLED`, bead declarat-f3f35f78).

## 0.2.5 (value-free spans, fss-41a05ca8)

`secret-scanner-v0.2.5-x86_64-unknown-linux-musl` is built with the same
static target command from commit
`686f49a9fcb069f8e17f4ff5cfac42c4d95d7f7b`. It adds
`--stdin --spans` (JSON byte offsets per finding, never the bytes) for
bead-rs redaction; detection is unchanged from 0.2.4. Its SHA-256 is
`36eeae16d378cbce32f8e77ee4689460896e491c03812ab1e4d27f08c8a1c610`. Installed as `~/.local/bin/secret-scanner` on codinghome; the
Forgejo pin is still `0.2.3` (see 0.2.4 above).

## 0.2.6 (batch spans, fss-40731332)

`secret-scanner-v0.2.6-x86_64-unknown-linux-musl` is built with the same
static target command from commit `ce75498e36ca9be573623bdc375192d5ccb76a1f`. It adds `--stdin --spans --nul`
(NUL-separated documents, each scanned on its own). Detection is unchanged
from 0.2.4. Its SHA-256 is `ce72ae68acfa2d9cf59b6c8233ca8a4257608b309e0a798c134aa6ac2aa2ae71`. Installed as `~/.local/bin/secret-scanner`
on codinghome; the Forgejo pin is still `0.2.3`.
