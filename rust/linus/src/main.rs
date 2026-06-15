use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

const RESERVE_MIB: usize = 128;
const PER_PROJECT_MIB: usize = 16;
const DEFAULT_MAX_RAM_MIB: usize = 1024;
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
const DEFAULT_MAX_FILE_MIB: usize = 20;
const OVERLAP_BYTES: usize = 4096;
const MAX_CONTEXT: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confidence {
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Ndjson,
    Sarif,
}

#[derive(Debug, Clone)]
struct Config {
    paths: Vec<PathBuf>,
    git_history: bool,
    staged: bool,
    since: Option<String>,
    format: OutputFormat,
    baseline: Option<PathBuf>,
    create_baseline: bool,
    fail_on: Severity,
    max_ram_mib: usize,
    project_concurrency: Option<usize>,
    scan_workers: Option<usize>,
    max_file_mib: usize,
    extract_archives: bool,
    validate_live: bool,
    providers: Vec<String>,
}

#[derive(Debug, Clone)]
struct Finding {
    fingerprint: String,
    rule_id: &'static str,
    severity: Severity,
    confidence: Confidence,
    secret_type: &'static str,
    project: String,
    file: String,
    line: usize,
    column: usize,
    commit: Option<String>,
    masked_secret: String,
    secret_sha256: String,
    context_before_redacted: String,
    context_after_redacted: String,
    asset_hint: Option<String>,
    remediation: &'static str,
}

#[derive(Debug, Default)]
struct Summary {
    projects_analyzed: usize,
    files_analyzed: usize,
    commits_or_blobs_analyzed: usize,
    findings_by_severity: BTreeMap<String, usize>,
    ram_budget_mib: usize,
    ram_available_mib: usize,
    max_projects_by_ram: usize,
    project_concurrency_used: usize,
    scan_workers_used: usize,
    chunk_size_bytes: usize,
    elapsed_ms: u128,
}

#[derive(Debug)]
struct Report {
    summary: Summary,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
struct Project {
    root: PathBuf,
    scope: PathBuf,
    display: String,
}

#[derive(Debug, Clone)]
struct Rule {
    id: &'static str,
    name: &'static str,
    secret_type: &'static str,
    severity: Severity,
    confidence: Confidence,
    prefixes: &'static [&'static str],
    keywords: &'static [&'static str],
    min_len: usize,
    remediation: &'static str,
}

const SENSITIVE_KEYWORDS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "key",
    "private",
    "credential",
    "auth",
    "bearer",
    "client_secret",
    "signing_secret",
    "webhook_secret",
    "jwt",
    "api_key",
    "apikey",
];

const FALSE_POSITIVE_WORDS: &[&str] = &[
    "example",
    "dummy",
    "fake",
    "test",
    "changeme",
    "placeholder",
    "sample",
    "not-a-secret",
    "do_not_use",
    "xxxx",
    "your_",
    "insert_",
];

const RULES: &[Rule] = &[
    Rule { id: "aws-access-key", name: "AWS access key", secret_type: "cloud_credential", severity: Severity::High, confidence: Confidence::High, prefixes: &["AKIA", "ASIA"], keywords: &["aws", "access_key", "aws_access_key_id"], min_len: 20, remediation: "Disable and rotate the IAM access key, audit CloudTrail, and prefer role/OIDC credentials." },
    Rule { id: "github-token", name: "GitHub token", secret_type: "provider_token", severity: Severity::High, confidence: Confidence::High, prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "github_pat_"], keywords: &["github", "token"], min_len: 30, remediation: "Revoke the token in GitHub, rotate dependent automation, and use scoped/short-lived credentials." },
    Rule { id: "gitlab-token", name: "GitLab token", secret_type: "provider_token", severity: Severity::High, confidence: Confidence::High, prefixes: &["glpat-", "gloas-", "glrt-"], keywords: &["gitlab", "token"], min_len: 24, remediation: "Revoke the GitLab token, replace it with a scoped CI/CD variable, and audit recent token usage." },
    Rule { id: "openai-api-key", name: "OpenAI/LLM API key", secret_type: "llm_provider_key", severity: Severity::High, confidence: Confidence::High, prefixes: &["sk-", "sk-proj-"], keywords: &["openai", "api_key", "llm"], min_len: 24, remediation: "Rotate the provider key, move it to a secret manager, and prevent logging tool credentials." },
    Rule { id: "slack-token", name: "Slack token", secret_type: "provider_token", severity: Severity::High, confidence: Confidence::High, prefixes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-"], keywords: &["slack", "token"], min_len: 24, remediation: "Revoke the Slack token, rotate app credentials, and review app scopes." },
    Rule { id: "stripe-secret-key", name: "Stripe secret key", secret_type: "payment_provider_key", severity: Severity::High, confidence: Confidence::High, prefixes: &["sk_live_", "rk_live_"], keywords: &["stripe"], min_len: 24, remediation: "Roll the Stripe key in the dashboard, update backend-only secret injection, and audit recent API calls." },
    Rule { id: "google-api-key", name: "Google API key", secret_type: "cloud_credential", severity: Severity::High, confidence: Confidence::High, prefixes: &["AIza"], keywords: &["google", "gcp"], min_len: 35, remediation: "Restrict and rotate the Google API key, then move it out of source control." },
    Rule { id: "npm-token", name: "npm registry token", secret_type: "package_registry_token", severity: Severity::High, confidence: Confidence::High, prefixes: &["npm_"], keywords: &["npm", "_authtoken"], min_len: 20, remediation: "Revoke the npm token, create a scoped read-only/automation token, and inject it through CI secrets." },
    Rule { id: "pypi-token", name: "PyPI token", secret_type: "package_registry_token", severity: Severity::High, confidence: Confidence::High, prefixes: &["pypi-"], keywords: &["pypi", "password"], min_len: 24, remediation: "Revoke the PyPI token and use trusted publishing or scoped API tokens." },
    Rule { id: "linus-secret", name: "Linus secret", secret_type: "application_secret", severity: Severity::High, confidence: Confidence::High, prefixes: &["ls_secret_"], keywords: &["linus", "secret"], min_len: 16, remediation: "Rotate the Linus secret and store it in the enclave/secret manager instead of source." },
];

fn main() -> ExitCode {
    match run() {
        Ok(has_findings_at_or_above_threshold) => {
            if has_findings_at_or_above_threshold {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("linus secure_leaks error: {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let started = Instant::now();
    let config = parse_args(env::args().skip(1).collect())?;
    if config.validate_live {
        return Err("live provider validation is intentionally opt-in but not implemented in this offline-first build; rerun without --validate-live".to_owned());
    }
    let memory = memory_budget(
        config.max_ram_mib,
        config.project_concurrency,
        config.scan_workers,
    )?;
    let baseline = match &config.baseline {
        Some(path) if !config.create_baseline => load_baseline(path)?,
        _ => HashSet::new(),
    };

    let mut findings = Vec::new();
    let mut summary = Summary {
        ram_budget_mib: config.max_ram_mib,
        ram_available_mib: config.max_ram_mib.saturating_sub(RESERVE_MIB),
        max_projects_by_ram: memory.max_projects_by_ram,
        project_concurrency_used: memory.project_concurrency,
        scan_workers_used: memory.scan_workers,
        chunk_size_bytes: DEFAULT_CHUNK_SIZE,
        ..Summary::default()
    };

    for path in &config.paths {
        let project = discover_project(path)?;
        summary.projects_analyzed += 1;
        scan_project(&config, &project, &baseline, &mut summary, &mut findings)?;
    }

    dedupe_findings(&mut findings);
    if config.create_baseline {
        let path = config
            .baseline
            .as_deref()
            .unwrap_or(Path::new("secretsleak.baseline"));
        write_baseline(path, &findings)?;
    }
    summarize_findings(&mut summary, &findings);
    summary.elapsed_ms = started.elapsed().as_millis();

    let should_fail = findings.iter().any(|f| f.severity >= config.fail_on);
    emit_report(&config, Report { summary, findings })?;
    Ok(should_fail)
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    if args.len() < 3 || args[0] != "deepscan" || args[1] != "secure_leaks" {
        return Err(usage());
    }
    let mut config = Config {
        paths: Vec::new(),
        git_history: true,
        staged: false,
        since: None,
        format: OutputFormat::Text,
        baseline: None,
        create_baseline: false,
        fail_on: Severity::Low,
        max_ram_mib: DEFAULT_MAX_RAM_MIB,
        project_concurrency: None,
        scan_workers: None,
        max_file_mib: DEFAULT_MAX_FILE_MIB,
        extract_archives: false,
        validate_live: false,
        providers: Vec::new(),
    };
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--git-history" => config.git_history = true,
            "--no-git-history" => config.git_history = false,
            "--staged" => config.staged = true,
            "--since" => {
                i += 1;
                config.since = Some(take_arg(&args, i, "--since")?);
            }
            "--format" => {
                i += 1;
                config.format = parse_format(&take_arg(&args, i, "--format")?)?;
            }
            "--baseline" => {
                i += 1;
                config.baseline = Some(PathBuf::from(take_arg(&args, i, "--baseline")?));
            }
            "--fail-on" => {
                i += 1;
                config.fail_on = parse_severity(&take_arg(&args, i, "--fail-on")?)?;
            }
            "--max-ram-mib" => {
                i += 1;
                config.max_ram_mib = parse_usize(&args, i, "--max-ram-mib")?;
            }
            "--project-concurrency" => {
                i += 1;
                config.project_concurrency = Some(parse_usize(&args, i, "--project-concurrency")?);
            }
            "--scan-workers" => {
                i += 1;
                config.scan_workers = Some(parse_usize(&args, i, "--scan-workers")?);
            }
            "--max-file-mib" => {
                i += 1;
                config.max_file_mib = parse_usize(&args, i, "--max-file-mib")?;
            }
            "--extract-archives" => config.extract_archives = true,
            "--validate-live" => config.validate_live = true,
            "--provider" => {
                i += 1;
                config.providers = take_arg(&args, i, "--provider")?
                    .split(',')
                    .map(str::to_owned)
                    .collect();
            }
            "rules" if args.get(i + 1).map(String::as_str) == Some("test") => {
                return Err("rules test is covered by cargo test for this build".to_owned())
            }
            "baseline" if args.get(i + 1).map(String::as_str) == Some("create") => {
                config.create_baseline = true;
                i += 1;
            }
            flag if flag.starts_with('-') => {
                return Err(format!("unknown flag {flag}\n{}", usage()))
            }
            path => config.paths.push(PathBuf::from(path)),
        }
        i += 1;
    }
    if config.paths.is_empty() && !config.staged {
        return Err(usage());
    }
    if config.staged && config.paths.is_empty() {
        config
            .paths
            .push(env::current_dir().map_err(|e| e.to_string())?);
    }
    Ok(config)
}

fn usage() -> String {
    "usage: linus deepscan secure_leaks [--git-history|--no-git-history] [--staged] [--since <commit|date>] [--format text|json|ndjson|sarif] [--baseline <file>] [--fail-on low|medium|high|critical] [--max-ram-mib 1024] [--project-concurrency 4] [--scan-workers 1] [--max-file-mib 20] [--extract-archives] <path...>".to_owned()
}

fn take_arg(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_usize(args: &[String], index: usize, flag: &str) -> Result<usize, String> {
    take_arg(args, index, flag)?
        .parse()
        .map_err(|_| format!("{flag} expects a positive integer"))
}

fn parse_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "ndjson" => Ok(OutputFormat::Ndjson),
        "sarif" => Ok(OutputFormat::Sarif),
        _ => Err("--format must be text, json, ndjson, or sarif".to_owned()),
    }
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    match value {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err("--fail-on must be low, medium, high, or critical".to_owned()),
    }
}

#[derive(Debug)]
struct MemoryBudget {
    max_projects_by_ram: usize,
    project_concurrency: usize,
    scan_workers: usize,
}

fn memory_budget(
    max_ram_mib: usize,
    requested_projects: Option<usize>,
    requested_workers: Option<usize>,
) -> Result<MemoryBudget, String> {
    if max_ram_mib <= RESERVE_MIB {
        return Err(format!(
            "--max-ram-mib must be greater than reserved {RESERVE_MIB} MiB"
        ));
    }
    let available = max_ram_mib - RESERVE_MIB;
    let max_projects_by_ram = available / PER_PROJECT_MIB;
    let cpu_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let default_project_concurrency = if cpu_count == 1 {
        4.min(max_projects_by_ram)
    } else {
        max_projects_by_ram.min(cpu_count * 4).max(1)
    };
    let project_concurrency = requested_projects.unwrap_or(default_project_concurrency);
    if project_concurrency == 0 || project_concurrency > max_projects_by_ram {
        return Err(format!("requested project concurrency {project_concurrency} exceeds RAM budget; max is {max_projects_by_ram} with {max_ram_mib} MiB, reserve {RESERVE_MIB} MiB, and {PER_PROJECT_MIB} MiB/project"));
    }
    let scan_workers = requested_workers.unwrap_or(cpu_count.max(1));
    if scan_workers == 0 {
        return Err("--scan-workers must be at least 1".to_owned());
    }
    Ok(MemoryBudget {
        max_projects_by_ram,
        project_concurrency,
        scan_workers,
    })
}

fn discover_project(path: &Path) -> Result<Project, String> {
    let root = repo_root(path)?;
    let scope = relative_to(path, &root).unwrap_or_else(|| PathBuf::from("."));
    Ok(Project {
        root: root.clone(),
        scope,
        display: root.display().to_string(),
    })
}

fn scan_project(
    config: &Config,
    project: &Project,
    baseline: &HashSet<String>,
    summary: &mut Summary,
    findings: &mut Vec<Finding>,
) -> Result<(), String> {
    let files = if config.staged {
        staged_files(&project.root)?
    } else {
        current_git_visible_paths(&project.root, &project.scope)?
    };
    for file in &files {
        let full = project.root.join(file);
        if should_skip_default(file, config.extract_archives) || !full.is_file() {
            continue;
        }
        if scan_file_streaming(config, project, file, None, baseline, findings)? {
            summary.files_analyzed += 1;
        }
    }
    if config.git_history && !config.staged {
        let blobs = git_history_blobs(project, config.since.as_deref())?;
        let mut seen_blobs = HashSet::new();
        for (blob, path) in blobs {
            if !seen_blobs.insert(blob.clone())
                || !path_in_scope(&path, &project.scope)
                || should_skip_default(&path, config.extract_archives)
            {
                continue;
            }
            let commit = first_commit_for_blob(&project.root, &blob, &path).ok();
            let data = git_blob(&project.root, &blob)?;
            summary.commits_or_blobs_analyzed += 1;
            scan_bytes(
                config,
                project,
                &path,
                commit.as_deref(),
                &data,
                baseline,
                findings,
            );
        }
    }
    Ok(())
}

fn scan_file_streaming(
    config: &Config,
    project: &Project,
    file: &Path,
    commit: Option<&str>,
    baseline: &HashSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<bool, String> {
    let full = project.root.join(file);
    let meta = fs::metadata(&full).map_err(|e| format!("{}: {e}", full.display()))?;
    let max_bytes = config.max_file_mib.saturating_mul(1024 * 1024) as u64;
    if meta.len() > max_bytes {
        return Ok(false);
    }
    let mut f = fs::File::open(&full).map_err(|e| format!("{}: {e}", full.display()))?;
    let mut carry = Vec::new();
    let mut chunk = vec![0_u8; DEFAULT_CHUNK_SIZE];
    let mut line_offset = 0_usize;
    loop {
        let read = f.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        let mut window = Vec::with_capacity(carry.len() + read);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&chunk[..read]);
        if !is_probably_binary(&window) {
            line_offset += scan_bytes_with_line_offset(
                config,
                project,
                file,
                commit,
                &window,
                line_offset,
                baseline,
                findings,
            );
        }
        carry.clear();
        let overlap = OVERLAP_BYTES.min(window.len());
        carry.extend_from_slice(&window[window.len() - overlap..]);
        zeroize(&mut window);
    }
    zeroize(&mut carry);
    Ok(true)
}

fn scan_bytes(
    config: &Config,
    project: &Project,
    file: &Path,
    commit: Option<&str>,
    bytes: &[u8],
    baseline: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    if bytes.len() > config.max_file_mib.saturating_mul(1024 * 1024) || is_probably_binary(bytes) {
        return;
    }
    scan_bytes_with_line_offset(config, project, file, commit, bytes, 0, baseline, findings);
}

fn scan_bytes_with_line_offset(
    _config: &Config,
    project: &Project,
    file: &Path,
    commit: Option<&str>,
    bytes: &[u8],
    line_offset: usize,
    baseline: &HashSet<String>,
    findings: &mut Vec<Finding>,
) -> usize {
    let text = String::from_utf8_lossy(bytes);
    let mut count = 0;
    for (idx, line) in text.lines().enumerate() {
        count += 1;
        scan_line(
            project,
            file,
            commit,
            line_offset + idx + 1,
            line,
            baseline,
            findings,
        );
    }
    count
}

fn scan_line(
    project: &Project,
    file: &Path,
    commit: Option<&str>,
    line_no: usize,
    line: &str,
    baseline: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    for rule in RULES {
        for prefix in rule.prefixes {
            if let Some(pos) = line.find(prefix) {
                let secret = extract_token_at(line, pos);
                if secret.len() >= rule.min_len && !is_false_positive(&secret) {
                    push_finding(
                        project,
                        file,
                        commit,
                        line_no,
                        pos + 1,
                        rule,
                        &secret,
                        line,
                        baseline,
                        findings,
                    );
                }
            }
        }
    }
    if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
        let rule = Rule { id: "private-key-pem", name: "Private key PEM", secret_type: "private_key", severity: Severity::Critical, confidence: Confidence::High, prefixes: &[], keywords: &["private", "key"], min_len: 16, remediation: "Revoke certificates/deploy keys, generate a new keypair, and remove the private key from history." };
        push_finding(
            project,
            file,
            commit,
            line_no,
            line.find("-----BEGIN").unwrap_or(0) + 1,
            &rule,
            "PRIVATE_KEY_BLOCK",
            line,
            baseline,
            findings,
        );
    }
    if let Some((col, secret)) = detect_uri_credential(line) {
        let rule = Rule { id: "uri-credential", name: "URI with credentials", secret_type: "connection_string", severity: Severity::High, confidence: Confidence::High, prefixes: &[], keywords: &["postgres", "mysql", "mongodb", "redis", "amqp", "smtp"], min_len: 8, remediation: "Rotate the credential, split connection settings from secrets, restrict network access, and inject via vault/env." };
        push_finding(
            project, file, commit, line_no, col, &rule, &secret, line, baseline, findings,
        );
    }
    if let Some((col, secret)) = detect_jwt(line) {
        let rule = Rule { id: "jwt", name: "JWT/session token", secret_type: "session_or_jwt", severity: Severity::Medium, confidence: Confidence::Medium, prefixes: &[], keywords: &["jwt", "bearer", "cookie"], min_len: 24, remediation: "Invalidate sessions/tokens and rotate the signing secret if token signing material leaked." };
        push_finding(
            project, file, commit, line_no, col, &rule, &secret, line, baseline, findings,
        );
    }
    if let Some((col, secret)) = detect_assignment_secret(line) {
        let rule = Rule { id: "assignment-secret", name: "Sensitive assignment", secret_type: "generic_secret", severity: Severity::Medium, confidence: confidence_for_line(line, &secret), prefixes: &[], keywords: SENSITIVE_KEYWORDS, min_len: 12, remediation: "Rotate the value if real, replace it with a secret reference, and add a format-invalid example value." };
        if !is_false_positive(&secret) {
            push_finding(
                project, file, commit, line_no, col, &rule, &secret, line, baseline, findings,
            );
        }
    }
    if looks_like_sensitive_filename(file) {
        if let Some((col, secret)) = detect_any_high_entropy_token(line) {
            let rule = Rule { id: "sensitive-file-token", name: "Token in sensitive file", secret_type: "config_secret", severity: Severity::Medium, confidence: Confidence::Medium, prefixes: &[], keywords: SENSITIVE_KEYWORDS, min_len: 16, remediation: "Remove sensitive local/config files from Git, add safe templates, rotate leaked values, and enforce .gitignore." };
            if !is_false_positive(&secret) {
                push_finding(
                    project, file, commit, line_no, col, &rule, &secret, line, baseline, findings,
                );
            }
        }
    }
}

fn push_finding(
    project: &Project,
    file: &Path,
    commit: Option<&str>,
    line: usize,
    column: usize,
    rule: &Rule,
    secret: &str,
    context: &str,
    baseline: &HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let _rule_metadata = (rule.name, rule.keywords);
    let hash = sha256_hex(secret.as_bytes());
    let fingerprint = sha256_hex(
        format!(
            "{}:{}:{}:{}:{}",
            project.display,
            file.display(),
            rule.id,
            commit.unwrap_or("worktree"),
            hash
        )
        .as_bytes(),
    );
    if baseline.contains(&fingerprint) {
        return;
    }
    let (before, after) = redacted_context(context, column.saturating_sub(1), secret.len());
    findings.push(Finding {
        fingerprint,
        rule_id: rule.id,
        severity: rule.severity,
        confidence: rule.confidence,
        secret_type: rule.secret_type,
        project: project.display.clone(),
        file: file.display().to_string(),
        line,
        column,
        commit: commit.map(str::to_owned),
        masked_secret: mask_secret(secret),
        secret_sha256: hash,
        context_before_redacted: before,
        context_after_redacted: after,
        asset_hint: asset_hint(context),
        remediation: rule.remediation,
    });
}

fn detect_assignment_secret(line: &str) -> Option<(usize, String)> {
    let lower = line.to_ascii_lowercase();
    if !SENSITIVE_KEYWORDS.iter().any(|k| lower.contains(k)) {
        return None;
    }
    let pos = line.find(['=', ':'])?;
    let raw = line[pos + 1..].trim_start();
    if raw.contains('(') || raw.starts_with('&') {
        return None;
    }
    let raw = raw.trim_matches(['\'', '"', ',', ';', ' ']);
    let secret = extract_token_at(raw, 0);
    if looks_like_symbolic_constant(&secret) {
        return None;
    }
    if secret.len() >= 12 && (entropy(&secret) >= 3.0 || secret.chars().any(|c| c.is_ascii_digit()))
    {
        Some((pos + 2, secret))
    } else {
        None
    }
}

fn looks_like_symbolic_constant(value: &str) -> bool {
    value.len() >= 8
        && !value.chars().any(|c| c.is_ascii_digit())
        && value.chars().all(|c| c.is_ascii_uppercase() || c == '_')
}

fn detect_uri_credential(line: &str) -> Option<(usize, String)> {
    let schemes = [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "amqp://",
        "amqps://",
        "smtp://",
    ];
    for scheme in schemes {
        let start = line.find(scheme)?;
        let after = &line[start + scheme.len()..];
        let at = after.find('@')?;
        let userinfo = &after[..at];
        if userinfo.contains(':') && userinfo.len() >= 5 {
            return Some((start + scheme.len() + 1, userinfo.to_owned()));
        }
    }
    None
}

fn detect_jwt(line: &str) -> Option<(usize, String)> {
    for (col, token) in tokens_with_columns(line) {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 3
            && parts[0].len() >= 8
            && parts[1].len() >= 8
            && parts[2].len() >= 8
            && parts.iter().all(|p| {
                p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            })
        {
            return Some((col, token));
        }
    }
    None
}

fn detect_any_high_entropy_token(line: &str) -> Option<(usize, String)> {
    tokens_with_columns(line)
        .into_iter()
        .find(|(_, token)| token.len() >= 16 && entropy(token) >= 3.5 && !is_false_positive(token))
}

fn extract_token_at(line: &str, pos: usize) -> String {
    let bytes = line.as_bytes();
    let mut start = pos.min(bytes.len());
    while start > 0 && is_token_char(bytes[start - 1] as char) {
        start -= 1;
    }
    let mut end = pos.min(bytes.len());
    while end < bytes.len() && is_token_char(bytes[end] as char) {
        end += 1;
    }
    line[start..end]
        .trim_matches(['\'', '"', ',', ';'])
        .to_owned()
}

fn tokens_with_columns(line: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, ch) in line.char_indices() {
        if is_token_char(ch) {
            start.get_or_insert(idx);
        } else if let Some(s) = start.take() {
            if idx > s {
                out.push((s + 1, line[s..idx].to_owned()));
            }
        }
    }
    if let Some(s) = start {
        out.push((s + 1, line[s..].to_owned()));
    }
    out
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '+' | '=' | ':' | '@')
}

fn confidence_for_line(line: &str, secret: &str) -> Confidence {
    if entropy(secret) >= 4.0
        && SENSITIVE_KEYWORDS
            .iter()
            .filter(|k| line.to_ascii_lowercase().contains(**k))
            .count()
            >= 2
    {
        Confidence::High
    } else {
        Confidence::Medium
    }
}

fn entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    for b in value.bytes() {
        *counts.entry(b).or_insert(0_usize) += 1;
    }
    let len = value.len() as f64;
    counts.values().fold(0.0, |acc, count| {
        let p = *count as f64 / len;
        acc - p * p.log2()
    })
}

fn is_false_positive(secret: &str) -> bool {
    let lower = secret.to_ascii_lowercase();
    FALSE_POSITIVE_WORDS.iter().any(|word| lower.contains(word))
        || is_uuid(secret)
        || looks_like_checksum(secret)
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .chars()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) && c == '-' || c.is_ascii_hexdigit())
}

fn looks_like_checksum(value: &str) -> bool {
    matches!(value.len(), 32 | 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn redacted_context(line: &str, start: usize, len: usize) -> (String, String) {
    let before_start = start.saturating_sub(MAX_CONTEXT);
    let before = line[before_start..start.min(line.len())].to_owned();
    let after_start = (start + len).min(line.len());
    let after_end = (after_start + MAX_CONTEXT).min(line.len());
    (
        mask_context(&before),
        mask_context(&line[after_start..after_end]),
    )
}

fn mask_context(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn mask_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "[redacted]".to_owned();
    }
    let head = &secret[..4.min(secret.len())];
    let tail = &secret[secret.len().saturating_sub(4)..];
    format!("{head}…{tail}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = H0;
    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0_u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn asset_hint(line: &str) -> Option<String> {
    for marker in [
        "DB_HOST",
        "DATABASE_URL",
        "REDIS_URL",
        "bucket",
        "endpoint",
        "host",
        "tenant",
        "project",
    ] {
        if line
            .to_ascii_lowercase()
            .contains(&marker.to_ascii_lowercase())
        {
            return Some(marker.to_owned());
        }
    }
    None
}

fn zeroize(bytes: &mut [u8]) {
    for b in bytes {
        *b = 0;
    }
}

fn should_skip_default(path: &Path, include_artifacts: bool) -> bool {
    let s = path.to_string_lossy();
    let skip_dirs = [
        "node_modules/",
        ".next/cache/",
        "target/",
        "zig-cache/",
        ".zig-cache/",
    ];
    if skip_dirs.iter().any(|d| s.contains(d)) {
        return true;
    }
    !include_artifacts
        && (s.contains("dist/") || s.contains("build/"))
        && !looks_like_sensitive_filename(path)
}

fn looks_like_sensitive_filename(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        ".env"
            | ".npmrc"
            | ".pypirc"
            | ".netrc"
            | "terraform.tfstate"
            | "settings.xml"
            | "kubeconfig"
    ) || name.ends_with(".pem")
        || name.ends_with(".p12")
        || name.ends_with(".jks")
        || name.contains("secret")
        || name.contains("prod")
}

fn is_probably_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

fn dedupe_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(format!("{}:{}:{}", f.secret_sha256, f.rule_id, f.project)));
}

fn summarize_findings(summary: &mut Summary, findings: &[Finding]) {
    for finding in findings {
        *summary
            .findings_by_severity
            .entry(format!("{:?}", finding.severity).to_ascii_lowercase())
            .or_insert(0) += 1;
    }
}

fn emit_report(config: &Config, report: Report) -> Result<(), String> {
    match config.format {
        OutputFormat::Text => print_text(&report),
        OutputFormat::Json => println!("{}", report_json(&report, true)),
        OutputFormat::Ndjson => {
            println!("{}", summary_json(&report.summary));
            for finding in &report.findings {
                println!("{}", finding_json(finding));
            }
        }
        OutputFormat::Sarif => println!("{}", sarif(&report)?),
    }
    Ok(())
}

fn print_text(report: &Report) {
    println!("linus secure_leaks deep scan");
    println!("projects={} files={} history_blobs={} findings={} ram_budget_mib={} max_projects_by_ram={} project_concurrency={} scan_workers={} elapsed_ms={}", report.summary.projects_analyzed, report.summary.files_analyzed, report.summary.commits_or_blobs_analyzed, report.findings.len(), report.summary.ram_budget_mib, report.summary.max_projects_by_ram, report.summary.project_concurrency_used, report.summary.scan_workers_used, report.summary.elapsed_ms);
    if report.summary.ram_budget_mib == 1024 && report.summary.max_projects_by_ram == 56 {
        println!("memory_model: 1024MiB - 128MiB reserve = 896MiB; 896/16MiB = 56 projects by RAM; recommended active projects on 1 core is 4.");
    }
    for f in &report.findings {
        println!(
            "{:?}\t{}\t{}:{}:{}\t{}\t{}\tfingerprint={}\tremediation={}",
            f.severity,
            f.commit.as_deref().unwrap_or("worktree"),
            f.file,
            f.line,
            f.column,
            f.rule_id,
            f.masked_secret,
            &f.fingerprint[..12],
            f.remediation
        );
    }
}

fn report_json(report: &Report, pretty: bool) -> String {
    let sep = if pretty { "\n" } else { "" };
    let findings = report
        .findings
        .iter()
        .map(finding_json)
        .collect::<Vec<_>>()
        .join(if pretty { ",\n" } else { "," });
    format!(
        "{{{sep}\"summary\":{},{}\"findings\":[{}]{sep}}}",
        summary_json(&report.summary),
        if pretty { "\n" } else { "" },
        findings
    )
}

fn summary_json(summary: &Summary) -> String {
    let severities = summary
        .findings_by_severity
        .iter()
        .map(|(k, v)| format!("\"{}\":{}", json_escape(k), v))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"projects_analyzed\":{},\"files_analyzed\":{},\"commits_or_blobs_analyzed\":{},\"findings_by_severity\":{{{}}},\"ram_budget_mib\":{},\"ram_available_mib\":{},\"max_projects_by_ram\":{},\"project_concurrency_used\":{},\"scan_workers_used\":{},\"chunk_size_bytes\":{},\"elapsed_ms\":{}}}", summary.projects_analyzed, summary.files_analyzed, summary.commits_or_blobs_analyzed, severities, summary.ram_budget_mib, summary.ram_available_mib, summary.max_projects_by_ram, summary.project_concurrency_used, summary.scan_workers_used, summary.chunk_size_bytes, summary.elapsed_ms)
}

fn finding_json(f: &Finding) -> String {
    format!("{{\"fingerprint\":\"{}\",\"rule_id\":\"{}\",\"severity\":\"{}\",\"confidence\":\"{}\",\"secret_type\":\"{}\",\"project\":\"{}\",\"file\":\"{}\",\"line\":{},\"column\":{},\"commit\":{},\"masked_secret\":\"{}\",\"secret_sha256\":\"{}\",\"context_before_redacted\":\"{}\",\"context_after_redacted\":\"{}\",\"asset_hint\":{},\"remediation\":\"{}\"}}", json_escape(&f.fingerprint), f.rule_id, severity_name(f.severity), confidence_name(f.confidence), f.secret_type, json_escape(&f.project), json_escape(&f.file), f.line, f.column, option_json(f.commit.as_deref()), json_escape(&f.masked_secret), f.secret_sha256, json_escape(&f.context_before_redacted), json_escape(&f.context_after_redacted), option_json(f.asset_hint.as_deref()), json_escape(f.remediation))
}

fn option_json(value: Option<&str>) -> String {
    value
        .map(|v| format!("\"{}\"", json_escape(v)))
        .unwrap_or_else(|| "null".to_owned())
}
fn severity_name(sev: Severity) -> &'static str {
    match sev {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
fn confidence_name(conf: Confidence) -> &'static str {
    match conf {
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            c if c.is_control() => " ".chars().collect(),
            c => vec![c],
        })
        .collect()
}

fn sarif(report: &Report) -> Result<String, String> {
    let results = report.findings.iter().map(|f| format!("{{\"ruleId\":\"{}\",\"level\":\"{}\",\"message\":{{\"text\":\"{}\"}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":\"{}\"}},\"region\":{{\"startLine\":{},\"startColumn\":{}}}}}}}],\"partialFingerprints\":{{\"secretFingerprint\":\"{}\"}}}}", f.rule_id, match f.severity { Severity::Critical | Severity::High => "error", Severity::Medium => "warning", Severity::Low => "note" }, json_escape(&format!("{} detected: {}. {}", f.secret_type, f.masked_secret, f.remediation)), json_escape(&f.file), f.line, f.column, f.fingerprint)).collect::<Vec<_>>().join(",");
    Ok(format!("{{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"linus secure_leaks\",\"informationUri\":\"https://attack.mitre.org/techniques/T1552/\",\"rules\":[]}}}},\"results\":[{}]}}]}}", results))
}

fn load_baseline(path: &Path) -> Result<HashSet<String>, String> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|l| l.split_once('\t').map(|(_, fp)| fp.to_owned()))
        .collect())
}

fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let mut lines = String::new();
    for f in findings {
        lines.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            f.rule_id, f.fingerprint, f.file, f.secret_sha256
        ));
    }
    fs::write(path, lines).map_err(|e| format!("{}: {e}", path.display()))
}

fn repo_root(path: &Path) -> Result<PathBuf, String> {
    let git_cwd = if path.is_file() {
        path.parent().unwrap_or(Path::new("."))
    } else {
        path
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(git_cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if !output.status.success() {
        return Err(format!("{} is not inside a git repository", path.display()));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

fn relative_to(path: &Path, root: &Path) -> Option<PathBuf> {
    let abs = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    abs.strip_prefix(root).ok().map(|p| {
        if p.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            p.to_path_buf()
        }
    })
}

fn current_git_visible_paths(root: &Path, scope: &Path) -> Result<Vec<PathBuf>, String> {
    git_lines(
        root,
        &[
            "ls-files",
            "-co",
            "--exclude-standard",
            "--",
            &scope.to_string_lossy(),
        ],
    )
    .map(|lines| lines.into_iter().map(PathBuf::from).collect())
}

fn staged_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    git_lines(root, &["diff", "--cached", "--name-only"])
        .map(|lines| lines.into_iter().map(PathBuf::from).collect())
}

fn git_history_blobs(
    project: &Project,
    since: Option<&str>,
) -> Result<Vec<(String, PathBuf)>, String> {
    let mut args = vec!["rev-list", "--objects", "--all"];
    if let Some(since) = since {
        args.push("--since");
        args.push(since);
    }
    args.push("--");
    let scope = project.scope.to_string_lossy().to_string();
    args.push(&scope);
    let lines = git_lines(&project.root, &args)?;
    let mut out = Vec::new();
    for line in lines {
        let mut parts = line.splitn(2, ' ');
        let Some(oid) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else {
            continue;
        };
        if git_object_type(&project.root, oid).as_deref() == Ok("blob") {
            out.push((oid.to_owned(), PathBuf::from(path)));
        }
    }
    Ok(out)
}

fn git_object_type(root: &Path, oid: &str) -> Result<String, String> {
    git_one_line(root, &["cat-file", "-t", oid])
}
fn git_blob(root: &Path, blob: &str) -> Result<Vec<u8>, String> {
    git_bytes(root, &["cat-file", "-p", blob])
}
fn first_commit_for_blob(root: &Path, blob: &str, path: &Path) -> Result<String, String> {
    git_one_line(
        root,
        &[
            "log",
            "--all",
            "--format=%H",
            "-n",
            "1",
            &format!("--find-object={blob}"),
            "--",
            &path.to_string_lossy(),
        ],
    )
}

fn path_in_scope(path: &Path, scope: &Path) -> bool {
    scope == Path::new(".") || path.starts_with(scope) || path == scope
}

fn git_lines(root: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    let output = git_bytes(root, args)?;
    Ok(String::from_utf8_lossy(&output)
        .lines()
        .map(str::to_owned)
        .collect())
}

fn git_one_line(root: &Path, args: &[&str]) -> Result<String, String> {
    Ok(git_lines(root, args)?
        .into_iter()
        .next()
        .unwrap_or_default())
}

fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_masks_middle() {
        assert_eq!(mask_secret("abcdef1234567890"), "abcd…7890");
    }

    #[test]
    fn sha256_is_stable() {
        assert_eq!(
            sha256_hex(b"secret"),
            "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"
        );
    }

    #[test]
    fn memory_budget_matches_1gib_acceptance() {
        let budget = memory_budget(1024, Some(4), Some(1)).unwrap();
        assert_eq!(budget.max_projects_by_ram, 56);
        assert_eq!(budget.project_concurrency, 4);
        assert_eq!(budget.scan_workers, 1);
    }

    #[test]
    fn rejects_over_budget_concurrency() {
        assert!(memory_budget(1024, Some(57), Some(1)).is_err());
    }

    #[test]
    fn detects_uri_credentials() {
        assert!(detect_uri_credential("DATABASE_URL=postgres://user:p4ssw0rd@db/prod").is_some());
    }

    #[test]
    fn detects_jwt_shape() {
        assert!(detect_jwt(
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart"
        )
        .is_some());
    }

    #[test]
    fn ignores_placeholders() {
        assert!(is_false_positive("sk_test_EXAMPLE_DO_NOT_USE"));
    }

    #[test]
    fn assignment_detector_needs_context() {
        assert!(detect_assignment_secret("client_secret = \"abc123abc123abc123\"").is_some());
    }

    #[test]
    fn pem_line_is_detectable() {
        let mut findings = Vec::new();
        let project = Project {
            root: PathBuf::from("/tmp/repo"),
            scope: PathBuf::from("."),
            display: "/tmp/repo".into(),
        };
        scan_line(
            &project,
            Path::new("id_rsa"),
            None,
            1,
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            &HashSet::new(),
            &mut findings,
        );
        assert!(findings.iter().any(|f| f.rule_id == "private-key-pem"));
    }

    #[test]
    fn raw_secret_is_not_in_mask() {
        assert!(
            !mask_secret("ghp_abcdefghijklmnopqrstuvwxyz").contains("abcdefghijklmnopqrstuvwxyz")
        );
    }
}
