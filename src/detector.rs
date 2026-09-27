use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_BYTES: u64 = 10_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub rule: &'static str,
}

#[derive(Default)]
struct FileState {
    last_line: usize,
    curl_line: Option<usize>,
    kubernetes_kind: Option<usize>,
    kubernetes_data: Option<usize>,
    kubernetes_reported: bool,
}

pub struct Scanner {
    findings: Vec<Finding>,
    seen: HashSet<(String, usize, &'static str)>,
    max_bytes: u64,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            seen: HashSet::new(),
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    #[must_use]
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            ..Self::new()
        }
    }

    pub fn scan_bytes(&mut self, path: &str, content: &[u8]) {
        if content.len() as u64 > self.max_bytes || content.contains(&0) {
            return;
        }

        let mut state = FileState::default();
        for (index, line) in content.split(|byte| *byte == b'\n').enumerate() {
            self.scan_line(path, index + 1, line, &mut state);
        }
    }

    pub(crate) fn scan_added_line(
        &mut self,
        path: &str,
        line_number: usize,
        line: &[u8],
        state: &mut StagedFileState,
    ) {
        self.scan_line(path, line_number, line, &mut state.inner);
    }

    /// Scan one file or recursively scan one directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a requested path cannot be read.
    pub fn scan_path(&mut self, path: &Path) -> io::Result<()> {
        if path.is_dir() {
            self.scan_directory(path)
        } else {
            self.scan_regular_file(path)
        }
    }

    /// Scan every file reported by `git ls-files` in the current repository.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if Git cannot be executed, Git fails, or a tracked
    /// file cannot be read.
    pub fn scan_tracked(&mut self) -> io::Result<()> {
        let output = std::process::Command::new("git")
            .args(["ls-files", "-z"])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("git ls-files failed"));
        }
        for raw_path in output.stdout.split(|byte| *byte == 0) {
            if raw_path.is_empty() {
                continue;
            }
            let path = PathBuf::from(String::from_utf8_lossy(raw_path).as_ref());
            self.scan_regular_file(&path)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn findings(mut self) -> Vec<Finding> {
        self.findings.sort();
        self.findings
    }

    #[must_use]
    pub fn summary(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.rule).or_insert(0) += 1;
        }
        counts
    }

    fn scan_directory(&mut self, root: &Path) -> io::Result<()> {
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    if entry.file_name() != ".git" {
                        pending.push(path);
                    }
                } else if file_type.is_file() {
                    self.scan_regular_file(&path)?;
                }
            }
        }
        Ok(())
    }

    fn scan_regular_file(&mut self, path: &Path) -> io::Result<()> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > self.max_bytes {
            return Ok(());
        }
        let content = fs::read(path)?;
        self.scan_bytes(&path.to_string_lossy(), &content);
        Ok(())
    }

    fn scan_line(&mut self, path: &str, line_number: usize, line: &[u8], state: &mut FileState) {
        if line_number > state.last_line.saturating_add(20) || line_number <= state.last_line {
            state.curl_line = None;
            state.kubernetes_kind = None;
            state.kubernetes_data = None;
            state.kubernetes_reported = false;
        }
        state.last_line = line_number;
        if contains_ascii_case_insensitive(line, b"curl") {
            state.curl_line = Some(line_number);
        }

        if contains_ascii_case_insensitive(line, b"gitleaks:allow")
            || contains_ascii_case_insensitive(line, b"secret-scanner:allow")
        {
            return;
        }

        let mut rules = Vec::with_capacity(4);
        let curl_context = state
            .curl_line
            .is_some_and(|curl_line| line_number.saturating_sub(curl_line) <= 5);
        detect_provider_tokens(line, &mut rules);
        detect_generic_assignment(line, &mut rules);
        detect_authorization_header(line, curl_context, &mut rules);
        detect_curl_user(line, curl_context, &mut rules);
        detect_private_key(line, &mut rules);
        detect_jwt(line, &mut rules);
        detect_basic_auth_uri(line, &mut rules);
        detect_kubernetes(line, line_number, state, &mut rules);

        for rule in rules {
            self.record(path, line_number, rule);
        }
    }

    fn record(&mut self, path: &str, line: usize, rule: &'static str) {
        let key = (path.to_owned(), line, rule);
        if self.seen.insert(key.clone()) {
            self.findings.push(Finding {
                path: key.0,
                line,
                rule,
            });
        }
    }
}

#[derive(Default)]
pub(crate) struct StagedFileState {
    inner: FileState,
}

#[derive(Clone, Copy)]
enum Alphabet {
    Alphanumeric,
    UpperAlphanumeric,
    Hex,
    Base64Url,
    Slack,
}

#[derive(Clone, Copy)]
struct PrefixRule {
    prefix: &'static [u8],
    rule: &'static str,
    minimum: usize,
    maximum: usize,
    exact: bool,
    alphabet: Alphabet,
}

const PREFIX_RULES: &[PrefixRule] = &[
    PrefixRule {
        prefix: b"AKIA",
        rule: "aws-access-key-id",
        minimum: 16,
        maximum: 16,
        exact: true,
        alphabet: Alphabet::UpperAlphanumeric,
    },
    PrefixRule {
        prefix: b"ASIA",
        rule: "aws-access-key-id",
        minimum: 16,
        maximum: 16,
        exact: true,
        alphabet: Alphabet::UpperAlphanumeric,
    },
    PrefixRule {
        prefix: b"ghp_",
        rule: "github-token",
        minimum: 36,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"gho_",
        rule: "github-token",
        minimum: 36,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"ghu_",
        rule: "github-token",
        minimum: 36,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"ghs_",
        rule: "github-token",
        minimum: 36,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"ghr_",
        rule: "github-token",
        minimum: 36,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"github_pat_",
        rule: "github-fine-grained-token",
        minimum: 22,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Base64Url,
    },
    PrefixRule {
        prefix: b"glpat-",
        rule: "gitlab-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Base64Url,
    },
    PrefixRule {
        prefix: b"xoxb-",
        rule: "slack-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Slack,
    },
    PrefixRule {
        prefix: b"xoxp-",
        rule: "slack-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Slack,
    },
    PrefixRule {
        prefix: b"xoxa-",
        rule: "slack-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Slack,
    },
    PrefixRule {
        prefix: b"xoxr-",
        rule: "slack-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Slack,
    },
    PrefixRule {
        prefix: b"sk_live_",
        rule: "stripe-access-token",
        minimum: 10,
        maximum: 99,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"rk_live_",
        rule: "stripe-access-token",
        minimum: 10,
        maximum: 99,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"sk_test_",
        rule: "stripe-access-token",
        minimum: 10,
        maximum: 99,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"rk_test_",
        rule: "stripe-access-token",
        minimum: 10,
        maximum: 99,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"AIza",
        rule: "google-api-key",
        minimum: 35,
        maximum: 35,
        exact: true,
        alphabet: Alphabet::Base64Url,
    },
    PrefixRule {
        prefix: b"npm_",
        rule: "npm-token",
        minimum: 36,
        maximum: 64,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"hf_",
        rule: "huggingface-token",
        minimum: 30,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Alphanumeric,
    },
    PrefixRule {
        prefix: b"sk-ant-",
        rule: "anthropic-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Base64Url,
    },
    PrefixRule {
        prefix: b"sk-proj-",
        rule: "openai-token",
        minimum: 20,
        maximum: 255,
        exact: false,
        alphabet: Alphabet::Base64Url,
    },
    PrefixRule {
        prefix: b"dop_v1_",
        rule: "digitalocean-token",
        minimum: 32,
        maximum: 128,
        exact: false,
        alphabet: Alphabet::Hex,
    },
    PrefixRule {
        prefix: b"dapi",
        rule: "databricks-token",
        minimum: 32,
        maximum: 64,
        exact: false,
        alphabet: Alphabet::Hex,
    },
];

const GENERIC_KEYWORDS: &[&[u8]] = &[
    b"access_token",
    b"api_key",
    b"apikey",
    b"api-token",
    b"auth_token",
    b"credential",
    b"passwd",
    b"password",
    b"private_key",
    b"secret",
    b"token",
];

fn detect_provider_tokens(line: &[u8], rules: &mut Vec<&'static str>) {
    for specification in PREFIX_RULES {
        for position in find_all(line, specification.prefix) {
            let start = position + specification.prefix.len();
            let length = line[start..]
                .iter()
                .take(specification.maximum.saturating_add(1))
                .take_while(|byte| alphabet_contains(specification.alphabet, **byte))
                .count();
            let valid_length = if specification.exact {
                length == specification.minimum
            } else {
                (specification.minimum..=specification.maximum).contains(&length)
            };
            if valid_length {
                rules.push(specification.rule);
                break;
            }
        }
    }

    for position in find_all(line, b"SG.") {
        let rest = &line[position + 3..];
        let first = rest.iter().take_while(|byte| is_base64_url(**byte)).count();
        if first >= 16 && rest.get(first) == Some(&b'.') {
            let second = rest[first + 1..]
                .iter()
                .take_while(|byte| is_base64_url(**byte))
                .count();
            if second >= 32 {
                rules.push("sendgrid-api-key");
                break;
            }
        }
    }

    for position in find_all(line, b"sk-") {
        let rest = &line[position + 3..];
        if rest.starts_with(b"ant-") || rest.starts_with(b"proj-") {
            continue;
        }
        let length = rest.iter().take_while(|byte| is_base64_url(**byte)).count();
        if length >= 20 {
            rules.push("openai-token");
            break;
        }
    }
}

fn detect_generic_assignment(line: &[u8], rules: &mut Vec<&'static str>) {
    for keyword in GENERIC_KEYWORDS {
        let mut search_from = 0;
        while let Some(relative) = find_ascii_case_insensitive(&line[search_from..], keyword) {
            let keyword_end = search_from + relative + keyword.len();
            let tail_end = line.len().min(keyword_end + 32);
            let tail = &line[keyword_end..tail_end];
            let Some(operator) = tail
                .iter()
                .position(|byte| matches!(byte, b'=' | b':' | b',' | b'>'))
            else {
                search_from = keyword_end;
                continue;
            };
            let mut value_start = keyword_end + operator + 1;
            while value_start < line.len()
                && matches!(
                    line[value_start],
                    b'=' | b':' | b'>' | b' ' | b'\t' | b'\'' | b'"' | b'`'
                )
            {
                value_start += 1;
            }
            if value_start >= line.len()
                || matches!(line[value_start], b'$' | b'{' | b'<' | b'[' | b'(')
            {
                search_from = keyword_end;
                continue;
            }
            let value_length = line[value_start..]
                .iter()
                .take(151)
                .take_while(|byte| is_generic_secret_byte(**byte))
                .count();
            if (10..=150).contains(&value_length) {
                let candidate = &line[value_start..value_start + value_length];
                if has_alpha_and_digit(candidate)
                    && shannon_entropy(candidate) >= 3.5
                    && !contains_stopword(candidate)
                {
                    rules.push("generic-api-key");
                    return;
                }
            }
            search_from = keyword_end;
        }
    }
}

fn detect_authorization_header(line: &[u8], curl_context: bool, rules: &mut Vec<&'static str>) {
    if let Some(position) = find_ascii_case_insensitive(line, b"authorization:") {
        let mut rest = trim_value_prefix(&line[position + b"authorization:".len()..]);
        for scheme in [b"bearer ".as_slice(), b"basic ", b"token ", b"api-token "] {
            if starts_ascii_case_insensitive(rest, scheme) {
                rest = trim_value_prefix(&rest[scheme.len()..]);
                break;
            }
        }
        if header_value_is_secret(rest) {
            rules.push("authorization-header");
            return;
        }
    }

    for (colon, _) in line.iter().enumerate().filter(|(_, byte)| **byte == b':') {
        let name_start = line[..colon]
            .iter()
            .rposition(|byte| matches!(byte, b' ' | b'\t' | b'\'' | b'"'))
            .map_or(0, |position| position + 1);
        let name = &line[name_start..colon];
        let api_key_name = contains_ascii_case_insensitive(name, b"apikey")
            || contains_ascii_case_insensitive(name, b"api-key");
        let token_name = name.len() <= 64
            && name
                .get(name.len().saturating_sub(5)..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b"token"));
        if curl_context
            && (api_key_name || token_name)
            && header_value_is_secret(&line[colon + 1..])
        {
            rules.push("authorization-header");
            return;
        }
    }
}

fn header_value_is_secret(value: &[u8]) -> bool {
    let value = trim_value_prefix(value);
    let length = value
        .iter()
        .take(256)
        .take_while(|byte| is_generic_secret_byte(**byte))
        .count();
    length >= 8 && shannon_entropy(&value[..length]) >= 2.75
}

fn detect_curl_user(line: &[u8], curl_context: bool, rules: &mut Vec<&'static str>) {
    if !curl_context {
        return;
    }
    let position = find_ascii_case_insensitive(line, b"--user")
        .map(|index| index + b"--user".len())
        .or_else(|| find_ascii_case_insensitive(line, b" -u").map(|index| index + 3));
    let Some(position) = position else {
        return;
    };
    let rest = trim_value_prefix(&line[position..]);
    let length = rest
        .iter()
        .take(256)
        .take_while(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'\'' | b'"'))
        .count();
    let candidate = &rest[..length];
    if candidate.len() >= 7
        && candidate.contains(&b':')
        && shannon_entropy(candidate) >= 2.0
        && !contains_stopword(candidate)
    {
        rules.push("curl-auth-user");
    }
}

fn detect_private_key(line: &[u8], rules: &mut Vec<&'static str>) {
    if contains_ascii_case_insensitive(line, b"-----BEGIN")
        && contains_ascii_case_insensitive(line, b"PRIVATE KEY-----")
    {
        rules.push("private-key");
    }
}

fn detect_jwt(line: &[u8], rules: &mut Vec<&'static str>) {
    for position in find_all(line, b"eyJ") {
        let candidate = &line[position..];
        let length = candidate
            .iter()
            .take(4096)
            .take_while(|byte| is_base64_url(**byte) || **byte == b'.')
            .count();
        let mut dots = 0;
        for byte in &candidate[..length] {
            dots += usize::from(*byte == b'.');
        }
        if length >= 40 && dots == 2 {
            rules.push("jwt");
            break;
        }
    }
}

fn detect_basic_auth_uri(line: &[u8], rules: &mut Vec<&'static str>) {
    let Some(scheme) = find_subslice(line, b"://") else {
        return;
    };
    let authority = &line[scheme + 3..];
    let authority_end = authority
        .iter()
        .position(|byte| matches!(byte, b'/' | b' ' | b'\t' | b'\'' | b'"'))
        .unwrap_or(authority.len());
    let authority = &authority[..authority_end];
    let Some(at) = authority.iter().position(|byte| *byte == b'@') else {
        return;
    };
    let credentials = &authority[..at];
    let Some(colon) = credentials.iter().position(|byte| *byte == b':') else {
        return;
    };
    let password = &credentials[colon + 1..];
    if password.len() >= 6 && shannon_entropy(password) >= 2.0 && !contains_stopword(password) {
        rules.push("basic-auth-uri");
    }
}

fn detect_kubernetes(
    line: &[u8],
    line_number: usize,
    state: &mut FileState,
    rules: &mut Vec<&'static str>,
) {
    if contains_ascii_case_insensitive(line, b"kind:")
        && contains_ascii_case_insensitive(line, b"secret")
    {
        state.kubernetes_kind = Some(line_number);
        state.kubernetes_reported = false;
    }
    if contains_ascii_case_insensitive(line, b"data:") {
        state.kubernetes_data = Some(line_number);
    }
    let nearby = state
        .kubernetes_kind
        .zip(state.kubernetes_data)
        .is_some_and(|(kind, data)| line_number.saturating_sub(kind.min(data)) <= 20);
    if nearby && !state.kubernetes_reported && yaml_base64_value(line) {
        rules.push("kubernetes-secret-yaml");
        state.kubernetes_reported = true;
    }
}

fn yaml_base64_value(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let value = trim_value_prefix(&line[colon + 1..]);
    let length = value
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        .count();
    length >= 10 && value[..length].iter().all(u8::is_ascii)
}

fn alphabet_contains(alphabet: Alphabet, byte: u8) -> bool {
    match alphabet {
        Alphabet::Alphanumeric => byte.is_ascii_alphanumeric(),
        Alphabet::UpperAlphanumeric => byte.is_ascii_uppercase() || byte.is_ascii_digit(),
        Alphabet::Hex => byte.is_ascii_hexdigit(),
        Alphabet::Base64Url => is_base64_url(byte),
        Alphabet::Slack => is_base64_url(byte) || byte == b'-',
    }
}

fn is_base64_url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_generic_secret_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'_' | b'-' | b'.' | b'=' | b'+' | b'/' | b'~' | b'@')
}

fn has_alpha_and_digit(value: &[u8]) -> bool {
    value.iter().any(u8::is_ascii_alphabetic) && value.iter().any(u8::is_ascii_digit)
}

fn contains_stopword(value: &[u8]) -> bool {
    [
        b"example".as_slice(),
        b"sample",
        b"dummy",
        b"placeholder",
        b"redacted",
        b"changeme",
        b"changeit",
        b"replace",
        b"your_",
        b"xxxxxx",
    ]
    .iter()
    .any(|word| contains_ascii_case_insensitive(value, word))
}

fn shannon_entropy(value: &[u8]) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u32; 256];
    for byte in value {
        counts[usize::from(*byte)] += 1;
    }
    let length = u32::try_from(value.len()).map_or(f64::from(u32::MAX), f64::from);
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let frequency = f64::from(count) / length;
            -frequency * frequency.log2()
        })
        .sum()
}

fn trim_value_prefix(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| {
        matches!(
            byte,
            b'=' | b':' | b'>' | b' ' | b'\t' | b'\'' | b'"' | b'`'
        )
    }) {
        value = &value[1..];
    }
    value
}

fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(move |(position, window)| (window == needle).then_some(position))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    find_ascii_case_insensitive(haystack, needle).is_some()
}

fn starts_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_for(content: &str) -> HashSet<&'static str> {
        let mut scanner = Scanner::new();
        scanner.scan_bytes("fixture.yaml", content.as_bytes());
        scanner
            .findings()
            .into_iter()
            .map(|finding| finding.rule)
            .collect()
    }

    fn synthetic() -> String {
        ["A7bQ9xL2", "mN4pR8sT", "3vW6yZ1c", "D5fG0hJk"].concat()
    }

    #[test]
    fn detects_common_provider_prefixes() {
        for specification in PREFIX_RULES {
            let alphabet = match specification.alphabet {
                Alphabet::UpperAlphanumeric => "A1B2C3D4E5F6G7H8",
                Alphabet::Hex => "a1b2c3d4e5f60718",
                Alphabet::Alphanumeric | Alphabet::Base64Url | Alphabet::Slack => {
                    "A7bQ9xL2mN4pR8sT"
                }
            };
            let suffix = alphabet
                .chars()
                .cycle()
                .take(specification.minimum)
                .collect::<String>();
            let mut candidate = specification.prefix.to_vec();
            candidate.extend_from_slice(suffix.as_bytes());
            let content = String::from_utf8(candidate).expect("synthetic token is ASCII");
            let rules = rules_for(&content);
            assert!(
                rules.contains(specification.rule),
                "expected {}",
                specification.rule
            );
        }

        let candidate = synthetic();
        let sendgrid = ["S", "G.", &candidate[..22], ".", &candidate, &candidate].concat();
        let legacy_openai = ["s", "k-", &candidate].concat();
        let rules = rules_for(&format!("{sendgrid}\n{legacy_openai}\n"));
        assert!(rules.contains("sendgrid-api-key"));
        assert!(rules.contains("openai-token"));
    }

    #[test]
    fn detects_contextual_and_structural_secrets() {
        let candidate = synthetic();
        let begin = ["-----BE", "GIN PRIVATE KEY-----"].concat();
        let jwt = [
            "eyJhbGciOiJIUzI1NiJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        .concat();
        let content = format!(
            "service_api_key = \"{candidate}\"\nAuthorization: Bearer {candidate}\ncurl --user operator:{candidate} https://example.invalid\n{begin}\n{jwt}\n" // secret-scanner:allow
        );
        let rules = rules_for(&content);
        assert!(rules.contains("generic-api-key"));
        assert!(rules.contains("authorization-header"));
        assert!(rules.contains("curl-auth-user"));
        assert!(rules.contains("private-key"));
        assert!(rules.contains("jwt"));
    }

    #[test]
    fn detects_api_headers_and_multiline_curl_user() {
        let candidate = synthetic();
        let content = format!(
            "curl https://example.invalid \\\n\n  -H 'X-Service-ApiKey: {candidate}' \\\n\n  -u operator:${candidate}\n" // secret-scanner:allow
        );
        let rules = rules_for(&content);
        assert!(rules.contains("authorization-header"));
        assert!(rules.contains("curl-auth-user"));
    }

    #[test]
    fn detects_kubernetes_secret_added_as_a_block() {
        let encoded = ["QWJjZGVm", "R2hpSmtM", "bW5PcFFy", "U3RVVldY", "WVo="].concat();
        let content = format!("kind: Secret\ndata:\n  password: {encoded}\n");
        assert!(rules_for(&content).contains("kubernetes-secret-yaml"));
    }

    #[test]
    fn ignores_placeholders_and_allow_comments() {
        let candidate = ["A7bQ9xL2", "mN4pR8sT"].concat();
        let content = format!(
            "api_key = your_api_key_here\npassword = changeme12345\napi_token = {candidate} # secret-scanner:allow\n"
        );
        assert!(rules_for(&content).is_empty());
    }
}
