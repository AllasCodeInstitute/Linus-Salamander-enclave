package llm_1ntruder
import ("regexp"; "strings")
var blocked_patterns = []string{"system prompt", "hidden instructions", "initial prompt", "developer message", "policy text", "print your rules"}
const replacement = "[REMOVED]"
func normalize_payload(payload string) string { return strings.ReplaceAll(strings.ReplaceAll(payload, "\x00", ""), "\r\n", "\n") }
func remove_blocked_patterns(normalized_payload string) string { cleaned_payload := normalized_payload; for _, blocked_pattern := range blocked_patterns { expression := regexp.MustCompile("(?i)" + regexp.QuoteMeta(blocked_pattern)); cleaned_payload = expression.ReplaceAllString(cleaned_payload, replacement) }; return cleaned_payload }
func escape_output(cleaned_payload string) string { replacer := strings.NewReplacer("&","&amp;","<","&lt;",">","&gt;","\"","&quot;","'","&#39;","`","&#96;"); return replacer.Replace(cleaned_payload) }
func Clean(threat string, payload string) string { normalized_payload := normalize_payload(payload); return escape_output(remove_blocked_patterns(normalized_payload)) }
type llm_1ntruder struct{}
var LLM_1ntruder = llm_1ntruder{}
func (llm_1ntruder) Clean(threat string, payload string) string { return Clean(threat, payload) }
