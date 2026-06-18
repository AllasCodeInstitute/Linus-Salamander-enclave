export const blocked_patterns = ["ignore previous instructions", "disregard all instructions", "system prompt", "developer message", "jailbreak", "reveal hidden"];
export const poetry_indicators = ["ignore", "system", "developer", "reveal"];
export const replacement = "[REMOVED]";

export function normalize_payload(payload: unknown): string {
  return String(payload ?? "").replace(/\0/g, "").replace(/\r\n/g, "\n");
}

export function extract_poetry_acrostic(normalized_payload: string): string {
  return normalized_payload
    .split("\n")
    .map((payload_line) => payload_line.trimStart().charAt(0).toLowerCase())
    .join("");
}

export function detect_poetry_prompt_injection(normalized_payload: string): boolean {
  const payload_lines = normalized_payload.split("\n").filter((payload_line) => payload_line.trim().length > 0);
  if (payload_lines.length < 3) {
    return false;
  }
  const poetry_acrostic = extract_poetry_acrostic(normalized_payload);
  return poetry_indicators.some((poetry_indicator) => poetry_acrostic.includes(poetry_indicator));
}

export function remove_blocked_patterns(normalized_payload: string, patterns = blocked_patterns): string {
  let cleaned_payload = normalized_payload;
  for (const blocked_pattern of patterns) {
    cleaned_payload = cleaned_payload.replace(new RegExp(blocked_pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), replacement);
  }
  return cleaned_payload;
}

export function neutralize_poetry_prompt_injection(cleaned_payload: string, normalized_payload: string): string {
  return detect_poetry_prompt_injection(normalized_payload) ? replacement : cleaned_payload;
}

export function escape_output(cleaned_payload: string): string {
  return cleaned_payload.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\"/g, "&quot;").replace(/'/g, "&#39;").replace(/`/g, "&#96;");
}

export function clean(threat: string, payload: unknown): string {
  const normalized_payload = normalize_payload(payload);
  const cleaned_payload = remove_blocked_patterns(normalized_payload);
  return escape_output(neutralize_poetry_prompt_injection(cleaned_payload, normalized_payload));
}

export const LLM_1ntruder = { clean };
