package llm_1ntruder

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var blocked_patterns = []string{"ignore previous instructions", "disregard all instructions", "system prompt", "developer message", "jailbreak", "reveal hidden"}
var poetry_indicators = []string{"ignore", "system", "developer", "reveal"}

const replacement = "[REMOVED]"

func normalize_payload(payload string) string {
	return strings.ReplaceAll(strings.ReplaceAll(payload, "\x00", ""), "\r\n", "\n")
}

func extract_poetry_acrostic(normalized_payload string) string {
	var poetry_acrostic strings.Builder
	for _, payload_line := range strings.Split(normalized_payload, "\n") {
		trimmed_payload_line := strings.TrimLeft(payload_line, " \t")
		if trimmed_payload_line == "" {
			continue
		}
		payload_rune, _ := utf8.DecodeRuneInString(trimmed_payload_line)
		poetry_acrostic.WriteString(strings.ToLower(string(payload_rune)))
	}
	return poetry_acrostic.String()
}

func detect_poetry_prompt_injection(normalized_payload string) bool {
	payload_line_count := 0
	for _, payload_line := range strings.Split(normalized_payload, "\n") {
		if strings.TrimSpace(payload_line) != "" {
			payload_line_count++
		}
	}
	if payload_line_count < 3 {
		return false
	}
	poetry_acrostic := extract_poetry_acrostic(normalized_payload)
	for _, poetry_indicator := range poetry_indicators {
		if strings.Contains(poetry_acrostic, poetry_indicator) {
			return true
		}
	}
	return false
}

func remove_blocked_patterns(normalized_payload string) string {
	cleaned_payload := normalized_payload
	for _, blocked_pattern := range blocked_patterns {
		expression := regexp.MustCompile("(?i)" + regexp.QuoteMeta(blocked_pattern))
		cleaned_payload = expression.ReplaceAllString(cleaned_payload, replacement)
	}
	return cleaned_payload
}

func neutralize_poetry_prompt_injection(cleaned_payload string, normalized_payload string) string {
	if detect_poetry_prompt_injection(normalized_payload) {
		return replacement
	}
	return cleaned_payload
}

func escape_output(cleaned_payload string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;", "`", "&#96;")
	return replacer.Replace(cleaned_payload)
}

func Clean(threat string, payload string) string {
	normalized_payload := normalize_payload(payload)
	cleaned_payload := remove_blocked_patterns(normalized_payload)
	return escape_output(neutralize_poetry_prompt_injection(cleaned_payload, normalized_payload))
}

type llm_1ntruder struct{}

var LLM_1ntruder = llm_1ntruder{}

func (llm_1ntruder) Clean(threat string, payload string) string { return Clean(threat, payload) }
