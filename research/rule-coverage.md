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

## Contextual and structural rules

| Rule ID | Detection |
|---|---|
| `generic-api-key` | Credential-like identifier, nearby operator, 10–150-character value, letters and digits, entropy ≥3.5, no common placeholder. Not an assignment: a value beginning with `//` (the rest of a URL after its scheme colon), and a comma preceded by anything other than identifier, quote or whitespace bytes (prose such as `token works (tags/list, image/0.9.4)`; the tuple form `("token", "value")` still matches) |
| `authorization-header` | Authorization header value of at least eight characters and entropy ≥2.75 |
| `curl-auth-user` | `curl -u/--user` value containing `:`, entropy ≥2.0, no common placeholder |
| `private-key` | PEM private-key begin marker |
| `jwt` | Three base64url-like segments beginning with the normal JWT header prefix |
| `basic-auth-uri` | URI authority containing username/password with a nontrivial password |
| `kubernetes-secret-yaml` | Newly added nearby `kind: Secret`, `data:`, and base64-shaped field |

## Known gaps

- Arbitrary passwords without a recognized identifier or structure.
- Secrets split across nonadjacent patch lines.
- Existing Kubernetes context when only the data value is added.
- Encoded, compressed, archived, binary, or generated secrets.
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
