import re
blocked_patterns = ['delete all', 'transfer money', 'send email', 'run command', 'drop table', 'shutdown']
replacement = "[REMOVED]"
def normalize_payload(payload):
    return str(payload if payload is not None else "").replace("\0", "").replace("\r\n", "\n")
def remove_blocked_patterns(normalized_payload, patterns=blocked_patterns):
    cleaned_payload = normalized_payload
    for blocked_pattern in patterns:
        cleaned_payload = re.sub(re.escape(blocked_pattern), replacement, cleaned_payload, flags=re.IGNORECASE)
    return cleaned_payload
def escape_output(cleaned_payload):
    return (cleaned_payload.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;").replace("'","&#39;").replace("`","&#96;"))
def clean(threat, payload):
    normalized_payload = normalize_payload(payload)
    return escape_output(remove_blocked_patterns(normalized_payload))
class LLM_1ntruder:
    clean = staticmethod(clean)
