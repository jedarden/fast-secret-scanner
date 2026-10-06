# Rule coverage

This is a curated high-value set, not the Gitleaks catalog.

## Provider prefixes

| Rule ID | Recognized prefix or shape |
|---|---|
| `aws-access-key-id` | `AKIA` / `ASIA` plus 16 uppercase alphanumeric characters |
| `github-token` | Classic GitHub token prefixes and bounded alphanumeric suffixes |
| `github-fine-grained-token` | Fine-grained GitHub personal-access-token prefix |
| `gitlab-token` | GitLab personal-access-token prefix |
| `slack-token` | Common Slack OAuth token prefixes |
| `stripe-access-token` | Stripe secret/restricted live and test prefixes |
| `google-api-key` | Google API key prefix and fixed suffix length |
| `sendgrid-api-key` | SendGrid three-part API-key shape |
| `npm-token` | npm automation/granular token prefix |
| `huggingface-token` | Hugging Face user-access-token prefix |
| `anthropic-token` | Anthropic API-key prefix |
| `openai-token` | OpenAI project and legacy API-key prefixes |
| `digitalocean-token` | DigitalOcean v1 token prefix with hexadecimal suffix |
| `databricks-token` | Databricks token prefix with hexadecimal suffix |

Provider formats change. Before changing these bounds, add runtime-constructed
positive and negative tests and benchmark the staged path.

Provider-prefix matches whose body is a documentation placeholder are not reported: a stopword (`your-`, `example`, …), an identifier-shaped body, or, for mixed-case alphabets only, a body with no digit and a single letter case (`sk-your-openai-api-key-here`, `ghp_` plus one repeated lowercase run). Uppercase-only and hex alphabets keep every match, because their real keys can be single-case and digit-free (fss-eeeb789c).

## Contextual and structural rules

| Rule ID | Detection |
|---|---|
| `generic-api-key` | Credential-like identifier, nearby operator, 10–150-character value, letters and digits, entropy ≥3.5, no common placeholder. A service-specific `_key` suffix additionally requires a direct `:` or `=` assignment and entropy ≥4.0. Not an assignment: a value beginning with `//` (the rest of a URL after its scheme colon); any byte other than identifier, quote or whitespace between the keyword and the operator (prose such as `token works (tags/list, image/0.9.4)` or `credential keys) -> name`; the tuple form `("token", "value")` still matches); a backslash there (a JSON-escaped `\n` puts the operator on another line of prose). Not a credential: an identifier-shaped value, i.e. separator-joined segments (`-_./=:+~@`) that are each a word with at most two letter/digit transitions and no mixed case plus digits (`findings_blocking=0`, `application/x-www-form-urlencoded`, `k8s/ord-devimprint/app`, `CHANGE_ME_32_CHARS`); random material alternates letters and digits and fails the bound. A value without a separator is never treated as an identifier (fss-eeeb789c) |
| `authorization-header` | Authorization header value of at least eight characters and entropy ≥2.75 that contains a digit or is at least 24 characters long; not a call expression (`name(`) and not identifier-shaped (`AWS4-HMAC-SHA256`). A single word such as `Forwarded` is prose (fss-eeeb789c) |
| `curl-auth-user` | `curl -u/--user` value containing `:`; qualify only the password (never username entropy): at least six bytes, entropy ≥2.0, and a digit, a non-alphanumeric byte, at least 24 bytes, or at least three adjacent alphabetic lower/upper-case changes. Reject common placeholders and short identifier-shaped passwords only when they have fewer than three alphabetic case changes and no `+`, `/` or `=`. Not a `date -u +%…` format or a variable reference (`${VAR}`, `$(cmd)`, `$NAME`, `$_name`; a `$` followed by mixed-case material is still a literal). Ordinary short documentation words do not qualify; opaque mixed-case, base64-like and long alphabetic positives remain covered. Long alphabetic words/identifiers are intentionally retained as possible credentials, not asserted clean (`fss-2272b3b4`) |
| `private-key` | PEM private-key begin marker |
| `jwt` | Three base64url-like segments beginning with the normal JWT header prefix |
| `basic-auth-uri` | URI authority containing username/password with a nontrivial password; not a variable or template reference (`${PASS}`, `{{ … }}`, `<password>`, `[password]`), not identifier-shaped, not equal to the username (`postgres:postgres@127.0.0.1`), and not the literal words `password`/`passwd`/`pass`/`secret`/`pwd` (fss-eeeb789c) |
| `kubernetes-secret-yaml` | Base64-shaped value in the `data:` or `stringData:` block (exact keys) of a document whose `kind:` is exactly `Secret`, within 20 lines. Not matched: `ExternalSecret`, `ClusterSecretStore`, `SecretStore`, `SealedSecret` (`encryptedData` is ciphertext), `metadata:`, YAML comment lines, URL values, identifier-shaped placeholders, and connection coordinates (`username`, `user`, `host`, `port`, `database`, `dbname`, `namespace`, `region`, `bucket`, `endpoint`, also as `_USER`-style suffixes). Before 0.2.4 any `kind:` line containing "secret" and any key ending in `data:` qualified, which flagged every ExternalSecret (fss-eeeb789c) |

## Known gaps

- Curl JSON semantics require a complete valid JSON document within the normal
  parser depth bound; malformed/truncated or deeper JSON retains raw scanning.
  Only the existing 256-source-byte curl capture window is decoded. In valid
  JSON, password qualification uses semantic bytes, and reported spans refer
  to their exact encoded bytes; LF/CR/tab escapes never supply password evidence.

- Arbitrary passwords without a recognized identifier or structure.
- Secrets split across nonadjacent patch lines.
- Existing Kubernetes context when only the data value is added.
- Encoded, compressed, archived, or generated secrets. Binary input is not
  inspected and produces an incomplete-scan exit status when selected.
- Provider formats not listed above.
- Full Git history and deleted historical values.
- Gitleaks allowlists, baselines, fingerprints, and provider validation.
- Filenames containing literal newline characters in staged mode.

These gaps are acceptable for the latency objective only because an
authoritative Gitleaks commit-range scan remains required.
# Generic assignment boundary

The generic rule does not treat hyphenated file names in notes as credential
keys. For example, a path with a `secret-` prefix followed by a comma and
another file name is not a credential assignment. Plain `secret = value` and
credential-like identifiers remain covered.
