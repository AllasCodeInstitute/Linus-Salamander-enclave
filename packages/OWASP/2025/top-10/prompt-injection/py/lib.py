import re
blocked_patterns = ["ignore previous instructions", "disregard all instructions", "system prompt", "developer message", "jailbreak", "reveal hidden"]
poetry_indicators = ["ignore", "system", "developer", "reveal"]
replacement = "[REMOVED]"

def normalize_payload(payload):
    return str(payload if payload is not None else "").replace("\0", "").replace("\r\n", "\n")

def extract_poetry_acrostic(normalized_payload):
    return "".join(payload_line.lstrip()[:1].lower() for payload_line in normalized_payload.split("\n"))

def detect_poetry_prompt_injection(normalized_payload):
    payload_lines = [payload_line for payload_line in normalized_payload.split("\n") if payload_line.strip()]
    if len(payload_lines) < 3:
        return False
    poetry_acrostic = extract_poetry_acrostic(normalized_payload)
    return any(poetry_indicator in poetry_acrostic for poetry_indicator in poetry_indicators)

def remove_blocked_patterns(normalized_payload, patterns=blocked_patterns):
    cleaned_payload = normalized_payload
    for blocked_pattern in patterns:
        cleaned_payload = re.sub(re.escape(blocked_pattern), replacement, cleaned_payload, flags=re.IGNORECASE)
    return cleaned_payload

def neutralize_poetry_prompt_injection(cleaned_payload, normalized_payload):
    return replacement if detect_poetry_prompt_injection(normalized_payload) else cleaned_payload

def escape_output(cleaned_payload):
    return (cleaned_payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;").replace("`", "&#96;"))

def clean(threat, payload):
    normalized_payload = normalize_payload(payload)
    cleaned_payload = remove_blocked_patterns(normalized_payload)
    return escape_output(neutralize_poetry_prompt_injection(cleaned_payload, normalized_payload))

class LLM_1ntruder:
    clean = staticmethod(clean)
