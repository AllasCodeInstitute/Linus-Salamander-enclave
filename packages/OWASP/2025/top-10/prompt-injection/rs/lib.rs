pub const BLOCKED_PATTERNS: &[&str] = &[
    "ignore previous instructions",
    "disregard all instructions",
    "system prompt",
    "developer message",
    "jailbreak",
    "reveal hidden",
];
pub const POETRY_INDICATORS: &[&str] = &["ignore", "system", "developer", "reveal"];
pub const REPLACEMENT: &str = "[REMOVED]";

pub fn normalize_payload(payload: &str) -> String {
    payload.replace('\0', "").replace("\r\n", "\n")
}

pub fn extract_poetry_acrostic(normalized_payload: &str) -> String {
    normalized_payload
        .lines()
        .filter_map(|payload_line| payload_line.trim_start().chars().next())
        .flat_map(|payload_character| payload_character.to_lowercase())
        .collect()
}

pub fn detect_poetry_prompt_injection(normalized_payload: &str) -> bool {
    let payload_line_count = normalized_payload
        .lines()
        .filter(|payload_line| !payload_line.trim().is_empty())
        .count();
    if payload_line_count < 3 {
        return false;
    }
    let poetry_acrostic = extract_poetry_acrostic(normalized_payload);
    POETRY_INDICATORS
        .iter()
        .any(|poetry_indicator| poetry_acrostic.contains(poetry_indicator))
}

pub fn remove_blocked_patterns(normalized_payload: &str) -> String {
    let mut cleaned_payload = normalized_payload.to_lowercase();
    for blocked_pattern in BLOCKED_PATTERNS {
        cleaned_payload = cleaned_payload.replace(&blocked_pattern.to_lowercase(), REPLACEMENT);
    }
    cleaned_payload
}

pub fn neutralize_poetry_prompt_injection(
    cleaned_payload: &str,
    normalized_payload: &str,
) -> String {
    if detect_poetry_prompt_injection(normalized_payload) {
        REPLACEMENT.to_string()
    } else {
        cleaned_payload.to_string()
    }
}

pub fn escape_output(cleaned_payload: &str) -> String {
    cleaned_payload
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace('`', "&#96;")
}

pub fn clean(_threat: &str, payload: &str) -> String {
    let normalized_payload = normalize_payload(payload);
    let cleaned_payload = remove_blocked_patterns(&normalized_payload);
    escape_output(&neutralize_poetry_prompt_injection(
        &cleaned_payload,
        &normalized_payload,
    ))
}

pub struct LLM1ntruder;
impl LLM1ntruder {
    pub fn clean(threat: &str, payload: &str) -> String {
        clean(threat, payload)
    }
}
