use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[derive(Debug, Clone, Copy)]
enum Severity {
    High,
    Medium,
}

#[derive(Debug)]
struct Finding {
    source: String,
    path: String,
    line: usize,
    kind: &'static str,
    severity: Severity,
    preview: String,
}

struct Rule {
    name: &'static str,
    severity: Severity,
    prefixes: &'static [&'static str],
    min_len: usize,
}

const RULES: &[Rule] = &[
    Rule {
        name: "AWS access key",
        severity: Severity::High,
        prefixes: &["AKIA", "ASIA"],
        min_len: 20,
    },
    Rule {
        name: "GitHub token",
        severity: Severity::High,
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "github_pat_"],
        min_len: 30,
    },
    Rule {
        name: "Slack token",
        severity: Severity::High,
        prefixes: &["xoxb-", "xoxp-", "xoxa-", "xoxr-"],
        min_len: 24,
    },
    Rule {
        name: "Stripe key",
        severity: Severity::High,
        prefixes: &["sk_live_", "rk_live_"],
        min_len: 24,
    },
    Rule {
        name: "Google API key",
        severity: Severity::High,
        prefixes: &["AIza"],
        min_len: 35,
    },
    Rule {
        name: "Linus secret",
        severity: Severity::High,
        prefixes: &["ls_secret_"],
        min_len: 16,
    },
];

const KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "secret",
    "client_secret",
    "private_key",
    "password",
    "passwd",
    "bearer",
    "jwt",
    "token",
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || args[1] != "deepscan" || args[2] != "secure_leaks" {
        eprintln!("usage: linus deepscan secure_leaks <path>");
        return ExitCode::from(2);
    }

    match scan(Path::new(&args[3])) {
        Ok(findings) => {
            print_report(&findings);
            if findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("linus secure_leaks error: {err}");
            ExitCode::from(2)
        }
    }
}

fn scan(path: &Path) -> Result<Vec<Finding>, String> {
    let root = repo_root(path)?;
    let rel_path = relative_to(path, &root);
    let tracked_scope = rel_path.as_deref().unwrap_or(Path::new("."));
    let allowed_paths = current_git_visible_paths(&root, tracked_scope)?;
    let mut findings = Vec::new();

    for file in &allowed_paths {
        let full = root.join(file);
        if let Ok(bytes) = std::fs::read(&full) {
            if is_probably_binary(&bytes) {
                continue;
            }
            scan_text(
                &mut findings,
                "worktree",
                file,
                &String::from_utf8_lossy(&bytes),
            );
        }
    }

    let grep_pattern = r#"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{20,}|ls_secret_[A-Za-z0-9_\-]{6,}|(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|bearer|jwt|token|secret)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=:;@\-]{12,}"#;
    let commits = git_lines(&root, ["rev-list", "--all"])?;
    let mut seen = HashSet::new();
    for commit in commits {
        let scope = tracked_scope.to_string_lossy();
        let output = Command::new("git")
            .args([
                "grep",
                "-I",
                "-n",
                "-E",
                grep_pattern,
                &commit,
                "--",
                &scope,
            ])
            .current_dir(&root)
            .output()
            .map_err(|e| format!("failed to run git grep: {e}"))?;
        if !output.status.success() {
            continue;
        }
        for row in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some((path, line_no, content)) = parse_git_grep_row(row, &commit) {
                let file = PathBuf::from(path);
                if !allowed_paths.contains(&file) {
                    continue;
                }
                let before = findings.len();
                scan_line(
                    &mut findings,
                    &commit[..12.min(commit.len())],
                    &file,
                    line_no,
                    content,
                );
                for f in &findings[before..] {
                    seen.insert(format!("{}:{}:{}:{}", f.source, f.path, f.line, f.kind));
                }
            }
        }
    }
    findings.dedup_by(|a, b| {
        a.source == b.source && a.path == b.path && a.line == b.line && a.kind == b.kind
    });
    Ok(findings)
}

fn parse_git_grep_row<'a>(row: &'a str, commit: &str) -> Option<(&'a str, usize, &'a str)> {
    let rest = row.strip_prefix(commit)?.strip_prefix(':')?;
    let (path, tail) = rest.split_once(':')?;
    let (line, content) = tail.split_once(':')?;
    Some((path, line.parse().ok()?, content))
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
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    abs.strip_prefix(root).ok().map(|p| {
        if p.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            p.to_path_buf()
        }
    })
}

fn current_git_visible_paths(root: &Path, scope: &Path) -> Result<Vec<PathBuf>, String> {
    let scope = scope.to_string_lossy();
    let lines = git_lines(
        root,
        ["ls-files", "-co", "--exclude-standard", "--", &scope],
    )?;
    Ok(lines
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| root.join(p).is_file())
        .collect())
}

fn git_lines<const N: usize>(root: &Path, args: [&str; N]) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
}

fn scan_text(findings: &mut Vec<Finding>, source: &str, path: &Path, text: &str) {
    for (idx, line) in text.lines().enumerate() {
        scan_line(findings, source, path, idx + 1, line);
    }
}

fn scan_line(findings: &mut Vec<Finding>, source: &str, path: &Path, line_no: usize, line: &str) {
    for rule in RULES {
        if rule
            .prefixes
            .iter()
            .any(|prefix| line.contains(prefix) && line.len() >= rule.min_len)
        {
            findings.push(finding(
                source,
                path,
                line_no,
                rule.name,
                rule.severity,
                line,
            ));
        }
    }
    let lower = line.to_ascii_lowercase();
    if KEYWORDS.iter().any(|k| lower.contains(k)) && has_assignment_secret(line) {
        findings.push(finding(
            source,
            path,
            line_no,
            "sensitive assignment",
            Severity::Medium,
            line,
        ));
    }
    if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
        findings.push(finding(
            source,
            path,
            line_no,
            "private key block",
            Severity::High,
            line,
        ));
    }
}

fn has_assignment_secret(line: &str) -> bool {
    let Some(pos) = line.find(['=', ':']) else {
        return false;
    };
    let value = line[pos + 1..]
        .trim()
        .trim_matches(['\'', '"', ',', ';', ' ']);
    value.len() >= 12
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
}

fn finding(
    source: &str,
    path: &Path,
    line: usize,
    kind: &'static str,
    severity: Severity,
    raw: &str,
) -> Finding {
    Finding {
        source: source.to_owned(),
        path: path.display().to_string(),
        line,
        kind,
        severity,
        preview: redact(raw),
    }
}

fn redact(raw: &str) -> String {
    let s = raw.trim();
    if s.len() <= 16 {
        return "[redacted]".to_owned();
    }
    format!(
        "{}…{}",
        &s[..8.min(s.len())],
        &s[s.len().saturating_sub(4)..]
    )
}

fn is_probably_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

fn print_report(findings: &[Finding]) {
    println!(
        "linus secure_leaks deep scan: {} finding(s)",
        findings.len()
    );
    for f in findings {
        println!(
            "{:?}\t{}\t{}:{}\t{}\t{}",
            f.severity, f.source, f.path, f.line, f.kind, f.preview
        );
    }
}
