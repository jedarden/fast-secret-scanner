use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_BYTES: u64 = 10_000_000;
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanSkips {
    pub oversized: usize,
    pub binary: usize,
}

impl ScanSkips {
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.oversized == 0 && self.binary == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub rule: &'static str,
}

/// Where a finding's sensitive bytes sit in content scanned with
/// [`Scanner::scan_bytes`]: half-open byte offsets from the start of that
/// content. A span locates bytes for a caller that already holds them (a
/// redaction tool); it never carries the bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Span {
    pub line: usize,
    pub start: usize,
    pub end: usize,
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
    unsafe_paths: HashSet<String>,
    skips: ScanSkips,
    max_bytes: u64,
    spans: Vec<Span>,
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
            unsafe_paths: HashSet::new(),
            skips: ScanSkips::default(),
            max_bytes: DEFAULT_MAX_BYTES,
            spans: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        Self {
            max_bytes: max_bytes.min(MAX_FILE_BYTES),
            ..Self::new()
        }
    }

    pub fn scan_bytes(&mut self, path: &str, content: &[u8]) {
        if content.len() as u64 > self.max_bytes {
            self.mark_oversized();
            return;
        }
        if content.contains(&0) {
            self.mark_binary();
            return;
        }

        let mut state = FileState::default();
        let mut offset = 0;
        for (index, line) in content.split(|byte| *byte == b'\n').enumerate() {
            self.scan_line(path, index + 1, line, Some(offset), &mut state);
            offset += line.len() + 1;
        }
    }

    pub(crate) fn scan_added_line(
        &mut self,
        path: &str,
        line_number: usize,
        line: &[u8],
        state: &mut StagedFileState,
    ) {
        self.scan_line(path, line_number, line, None, &mut state.inner);
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
        for finding in &mut self.findings {
            if self.unsafe_paths.contains(&finding.path) {
                finding.path.clear();
                finding.path.push_str("<redacted-path>");
            }
        }
        self.findings.sort();
        self.findings
    }

    /// Byte spans of every detection in content passed to
    /// [`Scanner::scan_bytes`], sorted by position. Staged and patch scans
    /// have no whole-content offsets and contribute none.
    #[must_use]
    pub fn spans(&self) -> Vec<Span> {
        let mut spans = self.spans.clone();
        spans.sort_by_key(|span| (span.start, span.end, span.rule));
        spans
    }

    #[must_use]
    pub fn summary(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.rule).or_insert(0) += 1;
        }
        counts
    }

    #[must_use]
    pub fn skips(&self) -> ScanSkips {
        self.skips
    }

    pub(crate) fn mark_binary(&mut self) {
        self.skips.binary = self.skips.binary.saturating_add(1);
    }

    pub(crate) fn mark_oversized(&mut self) {
        self.skips.oversized = self.skips.oversized.saturating_add(1);
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
            self.mark_oversized();
            return Ok(());
        }
        let content = fs::read(path)?;
        self.scan_bytes(&path.to_string_lossy(), &content);
        Ok(())
    }

    fn scan_line(
        &mut self,
        path: &str,
        line_number: usize,
        line: &[u8],
        line_offset: Option<usize>,
        state: &mut FileState,
    ) {
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

        let mut detections = Vec::with_capacity(4);
        let curl_context = state
            .curl_line
            .is_some_and(|curl_line| line_number.saturating_sub(curl_line) <= 5);
        detect_provider_tokens(line, &mut detections);
        detect_generic_assignment(line, &mut detections);
        detect_authorization_header(line, curl_context, &mut detections);
        detect_curl_user(line, curl_context, &mut detections);
        detect_private_key(line, &mut detections);
        detect_jwt(line, &mut detections);
        detect_basic_auth_uri(line, &mut detections);
        detect_kubernetes(line, line_number, state, &mut detections);

        if !detections.is_empty() && path_has_secret_shape(path) {
            self.unsafe_paths.insert(path.to_owned());
        }
        for detection in detections {
            // A matched value can also occur in a filename or stdin label.
            // Keep only a safety flag, never the value or a source-line copy.
            if !detection.sensitive.is_empty()
                && path
                    .as_bytes()
                    .windows(detection.sensitive.len())
                    .any(|part| part == detection.sensitive)
            {
                self.unsafe_paths.insert(path.to_owned());
            }
            // A JSON-encoded curl password can also occur in a label in its
            // semantic form. Check that bounded alias without retaining it.
            // Raw backslash literals may conservatively hide a decoded alias;
            // this affects only path safety, never findings or byte spans.
            if detection.rule == "curl-auth-user"
                && detection.sensitive.contains(&b'\\')
                && decode_json_fragment(detection.sensitive).is_some_and(|fragment| {
                    !fragment.bytes.is_empty()
                        && path
                            .as_bytes()
                            .windows(fragment.bytes.len())
                            .any(|part| part == fragment.bytes)
                })
            {
                self.unsafe_paths.insert(path.to_owned());
            }
            if let Some(line_offset) = line_offset {
                // Every detector returns a subslice of `line`, so its
                // position follows from the two addresses; no byte is copied.
                let start =
                    (detection.sensitive.as_ptr() as usize).saturating_sub(line.as_ptr() as usize);
                if start + detection.sensitive.len() <= line.len() {
                    let span = Span {
                        line: line_number,
                        start: line_offset + start,
                        end: line_offset + start + detection.sensitive.len(),
                        rule: detection.rule,
                    };
                    if !self.spans.contains(&span) {
                        self.spans.push(span);
                    }
                }
            }
            self.record(path, line_number, detection.rule);
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

struct Detection<'a> {
    rule: &'static str,
    sensitive: &'a [u8],
}

fn path_has_secret_shape(path: &str) -> bool {
    let mut detections = Vec::new();
    detect_provider_tokens(path.as_bytes(), &mut detections);
    detect_generic_assignment(path.as_bytes(), &mut detections);
    detect_jwt(path.as_bytes(), &mut detections);
    !detections.is_empty()
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
    // A standalone _KEY suffix covers service-specific key names without
    // treating every use of the English word "key" as an assignment.
    b"_key",
];

fn detect_provider_tokens<'a>(line: &'a [u8], detections: &mut Vec<Detection<'a>>) {
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
            let body = &line[start..start + length];
            if valid_length && !is_placeholder_body(specification.alphabet, body) {
                detections.push(Detection {
                    rule: specification.rule,
                    sensitive: &line[position..start + length],
                });
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
                detections.push(Detection {
                    rule: "sendgrid-api-key",
                    sensitive: &line[position..position + 3 + first + 1 + second],
                });
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
        if length >= 20 && !is_placeholder_body(Alphabet::Base64Url, &rest[..length]) {
            detections.push(Detection {
                rule: "openai-token",
                sensitive: &line[position..position + 3 + length],
            });
            break;
        }
    }
}

fn detect_generic_assignment<'a>(line: &'a [u8], detections: &mut Vec<Detection<'a>>) {
    for keyword in GENERIC_KEYWORDS {
        let mut search_from = 0;
        while let Some(relative) = find_ascii_case_insensitive(&line[search_from..], keyword) {
            let keyword_end = search_from + relative + keyword.len();
            if *keyword == b"_key"
                && line
                    .get(keyword_end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                search_from = keyword_end;
                continue;
            }
            // A path such as "secret-scan.md, research/report-2026.tsv" is not
            // an assignment. Do not let punctuation later in prose turn a
            // hyphenated filename into a credential key.
            if matches!(line.get(keyword_end), Some(b'-' | b'.' | b'/')) {
                search_from = keyword_end;
                continue;
            }
            let tail_end = line.len().min(keyword_end + 32);
            let tail = &line[keyword_end..tail_end];
            let Some(operator) = tail
                .iter()
                .position(|byte| matches!(byte, b'=' | b':' | b',' | b'>'))
            else {
                search_from = keyword_end;
                continue;
            };
            // A backslash between the keyword and the operator is an escape
            // sequence: in JSON-encoded text (bead checkpoints, logs) "\\n"
            // ends the line the keyword is on, so the operator and value that
            // follow belong to a different line of prose. A real key name
            // never contains a backslash.
            if tail[..operator].contains(&b'\\') {
                search_from = keyword_end;
                continue;
            }
            if *keyword == b"_key"
                && (!matches!(tail[operator], b'=' | b':')
                    || !tail[..operator]
                        .iter()
                        .all(|byte| matches!(byte, b' ' | b'\t' | b'\'' | b'"' | b'`')))
            {
                search_from = keyword_end;
                continue;
            }
            // Only key-name bytes may sit between the keyword and the
            // operator. In prose such as "the token works (tags/list,
            // image/0.9.4)" or "credential keys) -> name" the comma or the
            // arrow follows punctuation that no key ever contains. This also
            // keeps the comma's tuple form `("token", "value")`.
            if !tail[..operator]
                .iter()
                .all(|byte| is_key_suffix_byte(*byte))
            {
                search_from = keyword_end;
                continue;
            }
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
                // "//host/path" is the remainder of a URL whose scheme colon
                // was taken for the operator, not a credential.
                || line[value_start..].starts_with(b"//")
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
                let minimum_entropy = if *keyword == b"_key" { 4.0 } else { 3.5 };
                if has_alpha_and_digit(candidate)
                    && shannon_entropy(candidate) >= minimum_entropy
                    && !contains_stopword(candidate)
                    && !is_identifier_shaped(candidate)
                {
                    detections.push(Detection {
                        rule: "generic-api-key",
                        sensitive: candidate,
                    });
                    return;
                }
            }
            search_from = keyword_end;
        }
    }
}

fn detect_authorization_header<'a>(
    line: &'a [u8],
    curl_context: bool,
    detections: &mut Vec<Detection<'a>>,
) {
    if let Some(position) = find_ascii_case_insensitive(line, b"authorization:") {
        let mut rest = trim_value_prefix(&line[position + b"authorization:".len()..]);
        for scheme in [b"bearer ".as_slice(), b"basic ", b"token ", b"api-token "] {
            if starts_ascii_case_insensitive(rest, scheme) {
                rest = trim_value_prefix(&rest[scheme.len()..]);
                break;
            }
        }
        if let Some(sensitive) = header_secret_value(rest) {
            detections.push(Detection {
                rule: "authorization-header",
                sensitive,
            });
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
        if curl_context && (api_key_name || token_name) {
            if let Some(sensitive) = header_secret_value(&line[colon + 1..]) {
                detections.push(Detection {
                    rule: "authorization-header",
                    sensitive,
                });
                return;
            }
        }
    }
}

fn header_secret_value(value: &[u8]) -> Option<&[u8]> {
    let value = trim_value_prefix(value);
    let length = value
        .iter()
        .take(256)
        .take_while(|byte| is_generic_secret_byte(**byte))
        .count();
    let candidate = &value[..length];
    // A credential carries digits or is long. A single word ("Forwarded"),
    // or a function name followed by "(", is prose about the header.
    let token_like = candidate.iter().any(u8::is_ascii_digit) || candidate.len() >= 24;
    let call_expression = value.get(length) == Some(&b'(');
    (length >= 8
        && shannon_entropy(candidate) >= 2.75
        && token_like
        && !call_expression
        && !is_identifier_shaped(candidate))
    .then_some(candidate)
}

fn detect_curl_user<'a>(line: &'a [u8], curl_context: bool, detections: &mut Vec<Detection<'a>>) {
    if !curl_context {
        return;
    }
    let position = find_ascii_case_insensitive(line, b"--user")
        .map(|index| index + b"--user".len())
        .or_else(|| find_ascii_case_insensitive(line, b" -u").map(|index| index + 3));
    let Some(position) = position else {
        return;
    };
    let rest = &line[position..];
    let decoded = if curl_json_context(line, position) {
        decode_json_fragment(rest)
    } else {
        None
    };
    let semantic = decoded
        .as_ref()
        .map_or(rest, |fragment| fragment.bytes.as_slice());
    let value = trim_value_prefix(semantic);
    let prefix_length = semantic.len() - value.len();
    let length = value
        .iter()
        .take(256)
        .take_while(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'\'' | b'"'))
        .count();
    let candidate = &value[..length];
    let password = candidate
        .iter()
        .position(|byte| *byte == b':')
        .map_or(&candidate[..0], |colon| &candidate[colon + 1..]);
    // `date -u +%FT%T` near a curl call is a date format, not a user:password.
    if candidate.contains(&b'%') || is_placeholder_reference(password) {
        return;
    }
    // The username is context, not password evidence. Its entropy must not
    // turn an empty/short password or an ordinary documentation word into a
    // credential. Keep opaque mixed-case and symbol-bearing passwords too.
    let case_changes = password
        .windows(2)
        .filter(|pair| {
            pair.iter().all(u8::is_ascii_alphabetic)
                && pair[0].is_ascii_lowercase() != pair[1].is_ascii_lowercase()
        })
        .count();
    let token_like = password.iter().any(u8::is_ascii_digit)
        || password.iter().any(|byte| !byte.is_ascii_alphanumeric())
        || password.len() >= 24
        || case_changes >= 3;
    // A generic identifier predicate also accepts alphabetic base64 and
    // strongly alternating mixed-case segments. Those were detected before
    // this correction and must not be discarded as documentation names.
    let short_name = password.len() < 24
        && case_changes < 3
        && !password
            .iter()
            .any(|byte| matches!(byte, b'+' | b'/' | b'='))
        && is_identifier_shaped(password);
    if password.len() >= 6
        && token_like
        && shannon_entropy(password) >= 2.0
        && !contains_stopword(password)
        && !short_name
    {
        let sensitive = if let Some(fragment) = &decoded {
            let password_start = prefix_length + length - password.len();
            let password_end = prefix_length + length;
            &rest[fragment.ranges[password_start].0..fragment.ranges[password_end - 1].1]
        } else {
            &rest[prefix_length + length - password.len()..prefix_length + length]
        };
        detections.push(Detection {
            rule: "curl-auth-user",
            sensitive,
        });
    }
}

/// JSON semantics are trusted only for a complete valid document. `IgnoredAny`
/// validates structure without retaining parsed credential values. Invalid
/// JSON keeps the ordinary raw detector rather than becoming a clean bypass.
fn curl_json_context(line: &[u8], position: usize) -> bool {
    if !line
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'[' | b'"'))
    {
        return false;
    }
    let mut parser = serde_json::Deserializer::from_slice(line);
    if <serde::de::IgnoredAny as serde::Deserialize>::deserialize(&mut parser).is_err()
        || parser.end().is_err()
    {
        return false;
    }
    let mut quoted = false;
    let mut escaped = false;
    for byte in &line[..position] {
        if escaped {
            escaped = false;
        } else if quoted && *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            quoted = !quoted;
        }
    }
    quoted
}

struct JsonFragment {
    bytes: Vec<u8>,
    ranges: Vec<(usize, usize)>,
}

/// Decode at most the existing 256-source-byte curl token window. Each
/// semantic byte points to the full encoded character/escape that produced
/// it, so qualification never counts formatting and spans stay input-relative.
fn decode_json_fragment(source: &[u8]) -> Option<JsonFragment> {
    let mut result = JsonFragment {
        bytes: Vec::new(),
        ranges: Vec::new(),
    };
    let mut cursor = 0;
    while cursor < source.len().min(256) && source[cursor] != b'"' {
        let start = cursor;
        let character = if source[cursor] == b'\\' {
            cursor += 2;
            match *source.get(start + 1)? {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{08}',
                b'f' => '\u{0c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let high = u16::from_str_radix(
                        std::str::from_utf8(source.get(cursor..cursor + 4)?).ok()?,
                        16,
                    )
                    .ok()?;
                    cursor += 4;
                    let scalar = if (0xd800..=0xdbff).contains(&high) {
                        if source.get(cursor..cursor + 2)? != b"\\u" {
                            return None;
                        }
                        cursor += 2;
                        let low = u16::from_str_radix(
                            std::str::from_utf8(source.get(cursor..cursor + 4)?).ok()?,
                            16,
                        )
                        .ok()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return None;
                        }
                        cursor += 4;
                        0x10000 + ((u32::from(high) - 0xd800) << 10) + u32::from(low) - 0xdc00
                    } else {
                        u32::from(high)
                    };
                    char::from_u32(scalar)?
                }
                _ => return None,
            }
        } else {
            let width = match source[cursor] {
                0..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return None,
            };
            let character = std::str::from_utf8(source.get(cursor..cursor + width)?)
                .ok()?
                .chars()
                .next()?;
            cursor += character.len_utf8();
            character
        };
        if cursor > 256 {
            break;
        }
        let mut buffer = [0_u8; 4];
        let bytes = character.encode_utf8(&mut buffer).as_bytes();
        result.bytes.extend_from_slice(bytes);
        result
            .ranges
            .extend(std::iter::repeat_n((start, cursor), bytes.len()));
    }
    Some(result)
}

fn detect_private_key<'a>(line: &'a [u8], detections: &mut Vec<Detection<'a>>) {
    if contains_ascii_case_insensitive(line, b"-----BEGIN")
        && contains_ascii_case_insensitive(line, b"PRIVATE KEY-----")
    {
        detections.push(Detection {
            rule: "private-key",
            sensitive: line,
        });
    }
}

fn detect_jwt<'a>(line: &'a [u8], detections: &mut Vec<Detection<'a>>) {
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
            detections.push(Detection {
                rule: "jwt",
                sensitive: &candidate[..length],
            });
            break;
        }
    }
}

fn detect_basic_auth_uri<'a>(line: &'a [u8], detections: &mut Vec<Detection<'a>>) {
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
    let user = &credentials[..colon];
    let password = &credentials[colon + 1..];
    // `postgres:postgres@127.0.0.1` is a throwaway default, and a password
    // spelled "password" is documentation of the URL's shape.
    let default_or_label = password.eq_ignore_ascii_case(user)
        || [
            b"password".as_slice(),
            b"passwd",
            b"pass",
            b"secret",
            b"pwd",
        ]
        .iter()
        .any(|word| password.eq_ignore_ascii_case(word));
    if !default_or_label
        && password.len() >= 6
        && shannon_entropy(password) >= 2.0
        && !contains_stopword(password)
        && !is_placeholder_reference(password)
        && !is_identifier_shaped(password)
    {
        detections.push(Detection {
            rule: "basic-auth-uri",
            sensitive: password,
        });
    }
}

fn detect_kubernetes<'a>(
    line: &'a [u8],
    line_number: usize,
    state: &mut FileState,
    detections: &mut Vec<Detection<'a>>,
) {
    // Only a core `kind: Secret` carries values. ExternalSecret,
    // ClusterSecretStore, SecretStore and SealedSecret (ciphertext in
    // `encryptedData`) are references or encrypted, and used to match on the
    // substring "secret".
    if let Some(kind) = yaml_key_value(line, b"kind") {
        if kind == b"Secret" {
            state.kubernetes_kind = Some(line_number);
            state.kubernetes_data = None;
            state.kubernetes_reported = false;
        } else {
            state.kubernetes_kind = None;
            state.kubernetes_data = None;
        }
        return;
    }
    // The value block is exactly `data:` or `stringData:`; `metadata:` and
    // `encryptedData:` merely end in "data:".
    if yaml_key_value(line, b"data").is_some() || yaml_key_value(line, b"stringData").is_some() {
        state.kubernetes_data = Some(line_number);
        return;
    }
    let nearby = state
        .kubernetes_kind
        .zip(state.kubernetes_data)
        .is_some_and(|(kind, data)| {
            line_number > data && line_number.saturating_sub(kind.min(data)) <= 20
        });
    // A YAML comment documents the Secret; it is not one of its values.
    let comment = line
        .iter()
        .find(|byte| !matches!(byte, b' ' | b'\t'))
        .is_some_and(|byte| *byte == b'#');
    if nearby && !state.kubernetes_reported && !comment {
        if let Some(sensitive) = yaml_base64_value(line) {
            detections.push(Detection {
                rule: "kubernetes-secret-yaml",
                sensitive,
            });
            state.kubernetes_reported = true;
        }
    }
}

/// The value of a YAML mapping line whose key is exactly `key` (after
/// indentation and an optional list dash), with quotes and a trailing comment
/// removed. `None` when the line has a different key.
fn yaml_key_value<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut rest = line;
    while rest
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        rest = &rest[1..];
    }
    if rest.starts_with(b"- ") {
        rest = &rest[2..];
    }
    let rest = rest.strip_prefix(key)?.strip_prefix(b":")?;
    let rest = match rest.iter().position(|byte| *byte == b'#') {
        Some(comment) => &rest[..comment],
        None => rest,
    };
    let mut value = rest;
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'"' | b'\''))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'"' | b'\'' | b'\r'))
    {
        value = &value[..value.len() - 1];
    }
    Some(value)
}

fn yaml_base64_value(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    // Connection coordinates sit next to the credential in the same Secret
    // but are not secrets themselves.
    let key = line[..colon]
        .iter()
        .skip_while(|byte| matches!(byte, b' ' | b'\t' | b'-'))
        .copied()
        .collect::<Vec<u8>>();
    if [
        b"username".as_slice(),
        b"user",
        b"host",
        b"hostname",
        b"port",
        b"database",
        b"dbname",
        b"namespace",
        b"region",
        b"bucket",
        b"endpoint",
    ]
    .iter()
    .any(|name| {
        key.eq_ignore_ascii_case(name)
            || (key.len() > name.len() + 1
                && key[key.len() - name.len()..].eq_ignore_ascii_case(name)
                && matches!(key[key.len() - name.len() - 1], b'_' | b'-' | b'.'))
    }) {
        return None;
    }
    let value = trim_value_prefix(&line[colon + 1..]);
    let length = value
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        .count();
    // The whole value token, including the bytes base64 never contains, so
    // a URL ("postgresql://...") or a placeholder name
    // ("REPLACE_WITH_ACCESS_KEY") is not mistaken for its base64-looking
    // prefix. URLs are the basic-auth-uri rule's business.
    let token_length = value
        .iter()
        .take_while(|byte| !matches!(byte, b' ' | b'\t' | b'"' | b'\'' | b'#' | b'\r'))
        .count();
    let token = &value[..token_length];
    if find_subslice(token, b"://").is_some() || is_identifier_shaped(token) {
        return None;
    }
    (length >= 10 && value[..length].iter().all(u8::is_ascii)).then_some(&value[..length])
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

fn is_key_suffix_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'\'' | b'"' | b'`' | b' ' | b'\t')
}

/// Whether a candidate is a name rather than a credential: separator-joined
/// segments (paths, MIME types, host:port options, snake/kebab/SCREAMING case
/// names such as `findings_blocking=0` or `CHANGE_ME_32_CHARS`) where every
/// segment is a word with at most two letter/digit transitions (`k8s`, `v2`,
/// `2026a`). Random credentials alternate letters and digits throughout, so a
/// segment of them fails the transition bound. A candidate without a
/// separator is never treated as a name.
fn is_identifier_shaped(value: &[u8]) -> bool {
    let separator = |byte: &u8| {
        matches!(
            byte,
            b'-' | b'_' | b'.' | b'/' | b'=' | b':' | b'+' | b'~' | b'@'
        )
    };
    if !value.iter().any(separator) {
        return false;
    }
    value
        .split(separator)
        .filter(|segment| !segment.is_empty())
        .all(|segment| {
            // Mixed case is a word (CamelCase) only without digits; mixed
            // case plus digits is how random tokens look.
            let lower = segment.iter().any(u8::is_ascii_lowercase);
            let upper = segment.iter().skip(1).any(u8::is_ascii_uppercase);
            if lower && upper && segment.iter().any(u8::is_ascii_digit) {
                return false;
            }
            let transitions = segment
                .windows(2)
                .filter(|pair| pair[0].is_ascii_digit() != pair[1].is_ascii_digit())
                .count();
            transitions <= 2
        })
}

/// A templating reference standing in for a value: `${VAR}`, `$(cmd)`,
/// `$UPPER_CASE_VAR`, `$_lower_var`, `{{ .Values.x }}`, `<password>`, `[password]`. A `$`
/// followed by mixed-case material is a literal value, not a reference.
fn is_placeholder_reference(value: &[u8]) -> bool {
    // `$NAME` / `$_name`: one letter case plus digits and underscores, the
    // shape of a shell or environment variable name.
    let name = value.get(1..).unwrap_or_default();
    let env_reference = value.first() == Some(&b'$')
        && name
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && !(name.iter().any(u8::is_ascii_lowercase) && name.iter().any(u8::is_ascii_uppercase));
    env_reference
        || value.starts_with(b"$(")
        || value
            .first()
            .is_some_and(|byte| matches!(byte, b'{' | b'<' | b'['))
        || find_subslice(value, b"${").is_some()
        || find_subslice(value, b"{{").is_some()
}

/// Whether the body after a provider prefix is a documentation placeholder
/// (`sk-your-openai-key-here`, `ghp_` followed by one repeated letter class)
/// rather than generated key material. Random bodies over a mixed-case
/// alphabet carry digits and both letter cases; uppercase-only or hex
/// alphabets are exempt from that half of the test because their real keys
/// can be single-case and digit-free.
fn is_placeholder_body(alphabet: Alphabet, body: &[u8]) -> bool {
    if contains_stopword(body) || is_identifier_shaped(body) {
        return true;
    }
    if matches!(alphabet, Alphabet::UpperAlphanumeric | Alphabet::Hex) {
        return false;
    }
    let digits = body.iter().any(u8::is_ascii_digit);
    let lower = body.iter().any(u8::is_ascii_lowercase);
    let upper = body.iter().any(u8::is_ascii_uppercase);
    !digits && (!lower || !upper)
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
        b"your-",
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
    fn curl_password_evidence_is_independent_of_username() {
        for user in ["operator".to_owned(), synthetic()] {
            for password in [
                "",
                "word",
                "alpha",
                "password",
                "Forwarded",
                "ordinary",
                "CHANGE_ME_32_CHARS",
                "${PASSWORD}",
                "$_pass",
                "$(lookup)",
            ] {
                let line = format!("curl --user {user}:{password} https://example.invalid");
                assert!(!rules_for(&line).contains("curl-auth-user"));
            }
        }
        for password in [
            synthetic(),
            ["aB", "cD", "eF", "gH"].concat(),
            ["aBcD", "-", "eFgH"].concat(),
            ["abcdefghi", "+", "jklmnopqr", "+", "stuvwxyz"].concat(),
            ["ab", "!", "Cd", "?", "ef"].concat(),
            ["baf", "gih", "jol", "mun", "pev", "ruz", "sot", "qxy"].concat(),
        ] {
            for option in ["-u", "--user"] {
                let line = format!("curl {option} operator:{password} https://example.invalid");
                let mut detections = Vec::new();
                detect_curl_user(line.as_bytes(), true, &mut detections);
                assert_eq!(detections.len(), 1);
                assert_eq!(detections[0].rule, "curl-auth-user");
                assert_eq!(detections[0].sensitive, password.as_bytes());
            }
        }
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

    #[test]
    fn detects_service_key_suffix_without_matching_prose_or_placeholders() {
        let candidate = synthetic();
        assert!(rules_for(&format!("relay_key: {candidate}")).contains("generic-api-key"));
        assert!(rules_for(&format!("relay_keyboard: {candidate}")).is_empty());
        assert!(rules_for(&format!("monkey: {candidate}")).is_empty());
        assert!(rules_for(&format!("the relay_key is stored here: {candidate}")).is_empty());
        assert!(rules_for(&format!("relay_key, {candidate}")).is_empty());
        assert!(rules_for("relay_key: your_key_here123").is_empty());

        let path = format!("fixture-{candidate}.txt");
        let mut scanner = Scanner::new();
        scanner.scan_bytes(&path, format!("relay_key: {candidate}\n").as_bytes());
        assert_eq!(scanner.findings()[0].path, "<redacted-path>");
    }

    #[test]
    fn does_not_treat_hyphenated_paths_in_notes_as_assignments() {
        let note = "Affected paths: secret-scan.md, research/worktree-benchmark-2026-09-28.tsv";
        assert!(rules_for(note).is_empty());
        assert!(rules_for(&format!("secret = {}", synthetic())).contains("generic-api-key"));
    }

    #[test]
    fn does_not_treat_a_url_scheme_colon_as_an_assignment() {
        // The keyword is followed, within the operator window, by the colon
        // of "https:"; the rest of the URL has letters, a digit and enough
        // entropy to pass as a value.
        let host = ["index.", "docker.io"].concat();
        let note = format!("the registry token lives in auths[\"https://{host}/v1/\"]");
        assert!(rules_for(&note).is_empty());
        let assigned = format!("token: {}", synthetic());
        assert!(rules_for(&assigned).contains("generic-api-key"));
    }

    #[test]
    fn does_not_treat_a_prose_comma_as_an_assignment() {
        let image = ["myorg-app", "/0.9.4"].concat();
        let note = format!("the token works (tags/list, {image}) against the registry");
        assert!(rules_for(&note).is_empty());
        // The tuple form is still an assignment.
        let tuple = format!("(\"api_token\", \"{}\")", synthetic());
        assert!(rules_for(&tuple).contains("generic-api-key"));
        let suffixed = format!("token_value, {}", synthetic());
        assert!(rules_for(&suffixed).contains("generic-api-key"));
    }

    // fss-eeeb789c: shapes seen as false positives on 2026-10-03 in sharded
    // bead checkpoints and declarative-config. Each negative case is paired
    // with a positive case so the narrowing cannot silently remove a rule.

    #[test]
    fn kubernetes_rule_targets_only_core_secret_values() {
        let external = "apiVersion: external-secrets.io/v1\nkind: ExternalSecret\nmetadata:\n  name: app\n  namespace: app\nspec:\n  refreshInterval: 1h\n  secretStoreRef:\n    name: openbao\n    kind: ClusterSecretStore\n  data:\n    - secretKey: TOKEN\n";
        assert!(rules_for(external).is_empty());
        // SealedSecret ciphertext is hundreds of characters long.
        let encrypted = ["AgBy3i4OJSWK", "+PiTySYZZA9rO", "43cGDEq"]
            .concat()
            .repeat(12);
        let sealed = format!(
            "kind: SealedSecret\nmetadata:\n  name: app\nspec:\n  encryptedData:\n    token: {encrypted}\n"
        );
        assert!(rules_for(&sealed).is_empty());
        let encoded = ["QWJjZGVm", "R2hpSmtM", "bW5PcFFy"].concat();
        let documented = format!(
            "kind: Secret\nmetadata:\n  name: app\nstringData:\n  # Account ID: {encoded}\n  username: applicationuser\n  DB_HOST: databaseserver01\n  url: postgresql://app:${{PASSWORD}}@db:5432/app\n  key: REPLACE_WITH_ACCESS_KEY\n"
        );
        assert!(rules_for(&documented).is_empty());
        let real = format!("kind: Secret\nmetadata:\n  name: app\ndata:\n  password: {encoded}\n");
        assert!(rules_for(&real).contains("kubernetes-secret-yaml"));
    }

    #[test]
    fn generic_rule_ignores_escaped_newlines_arrows_and_identifiers() {
        let candidate = synthetic();
        let escaped = format!("\"notes\":\"use the token\\n     - client_id: {candidate}\"");
        let arrow = "the credential keys) -> rotation-2026ab1c and more".to_owned();
        let names = [
            "bead doctor --scope secrets`: findings_blocking=0, advisory=12",
            "token: application/x-www-form-urlencoded",
            "the secret: k8s/ord-devimprint/commitgraph/externalsecret",
            "credentials: aaaaaaaaa-a1-bbbbbbbbbbb",
            "POSTGRES_PASSWORD: CHANGE_ME_SECURE_PASSWORD_32_CHARS",
        ];
        assert!(!rules_for(&escaped).contains("generic-api-key"));
        assert!(!rules_for(&arrow).contains("generic-api-key"));
        for name in names {
            assert!(!rules_for(name).contains("generic-api-key"), "{name}");
        }
        let real = format!("token: {candidate}");
        assert!(rules_for(&real).contains("generic-api-key"));
        let hyphenated = format!("api_key=k3j9x-{candidate}");
        assert!(rules_for(&hyphenated).contains("generic-api-key"));
    }

    #[test]
    fn header_and_userinfo_rules_ignore_prose_and_placeholders() {
        for prose in [
            "Authorization: Forwarded",
            "Authorization: buildAuthorizationHeader()",
            "--header \"Authorization: AWS4-HMAC-SHA256 Credential=${AWS_KEY}\"",
            "url: postgresql://postgres:postgres@127.0.0.1:5432/app",
            "DATABASE_URL=postgresql://app:${DB_PASSWORD}@db:5432/app",
            "# Format: postgresql://user:password@host:port/database",
        ] {
            assert!(rules_for(prose).is_empty(), "{prose}");
        }
        let date =
            "curl -s https://example.invalid \\\n  -H \"X-At: $(date -u +%Y-%m-%dT%H:%M:%SZ)\"\n";
        assert!(!rules_for(date).contains("curl-auth-user"));
        let shell = "curl -fsS -u \"$_user:$_pass\" https://example.invalid\n";
        assert!(!rules_for(shell).contains("curl-auth-user"));
        let candidate = synthetic();
        let bearer = format!("Authorization: Bearer {candidate}");
        assert!(rules_for(&bearer).contains("authorization-header"));
        let uri = format!("postgresql://app:{candidate}@db:5432/app");
        assert!(rules_for(&uri).contains("basic-auth-uri"));
    }

    #[test]
    fn provider_prefixes_ignore_documentation_placeholders() {
        let lowercase = "a".repeat(36);
        let placeholders = [
            ["OPENAI_API_KEY: \"sk-", "your-openai-api-key-here\""].concat(),
            ["api-key: \"sk-", "PLACEHOLDER_REPLACE_WITH_REAL_KEY\""].concat(),
            format!("token={}{lowercase}", "ghp_"),
        ];
        for placeholder in &placeholders {
            assert!(rules_for(placeholder).is_empty(), "{placeholder}");
        }
        let real = format!(
            "token={}{}",
            "ghp_",
            ["A7bQ9xL2mN4pR8sT", "3vW6yZ1cD5fG0hJk", "Qw3E"].concat()
        );
        assert!(rules_for(&real).contains("github-token"));
    }
}
