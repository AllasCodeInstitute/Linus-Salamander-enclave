pub const BLOCKED_PATTERNS: &[&str] = &["<script", "javascript:", "onerror=", "{{", "}}", "$("];
pub const REPLACEMENT: &str = "[REMOVED]";
pub fn normalize_payload(payload: &str) -> String { payload.replace('\0', "").replace("\r\n", "\n") }
pub fn remove_blocked_patterns(normalized_payload: &str) -> String { let mut cleaned_payload = normalized_payload.to_string(); for blocked_pattern in BLOCKED_PATTERNS { cleaned_payload = cleaned_payload.to_lowercase().replace(&blocked_pattern.to_lowercase(), REPLACEMENT); } cleaned_payload }
pub fn escape_output(cleaned_payload: &str) -> String { cleaned_payload.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('\"',"&quot;").replace('\'',"&#39;").replace('`',"&#96;") }
pub fn clean(_threat: &str, payload: &str) -> String { let normalized_payload = normalize_payload(payload); escape_output(&remove_blocked_patterns(&normalized_payload)) }
pub struct LLM1ntruder;
impl LLM1ntruder { pub fn clean(threat: &str, payload: &str) -> String { clean(threat, payload) } }
