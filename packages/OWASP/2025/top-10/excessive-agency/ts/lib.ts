export const blocked_patterns = ['delete all', 'transfer money', 'send email', 'run command', 'drop table', 'shutdown'];
export const replacement = "[REMOVED]";
export function normalize_payload(payload: unknown): string { return String(payload ?? "").replace(/\0/g, "").replace(/\r\n/g, "\n"); }
export function remove_blocked_patterns(normalized_payload: string, patterns = blocked_patterns): string { let cleaned_payload = normalized_payload; for (const blocked_pattern of patterns) { cleaned_payload = cleaned_payload.replace(new RegExp(blocked_pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), replacement); } return cleaned_payload; }
export function escape_output(cleaned_payload: string): string { return cleaned_payload.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;").replace(/'/g,"&#39;").replace(/`/g,"&#96;"); }
export function clean(threat: string, payload: unknown): string { const normalized_payload = normalize_payload(payload); return escape_output(remove_blocked_patterns(normalized_payload)); }
export const LLM_1ntruder = { clean };
