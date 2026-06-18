package llm_1ntruder
import ("strings"; "testing")
func TestVulnerability(t *testing.T) { if !strings.Contains(vulnerable_scenario("x system prompt"), "system prompt") { t.Fatal("expected vulnerable marker") } }
func TestDefense(t *testing.T) { if strings.Contains(LLM_1ntruder.Clean("System Prompt Leakage", "x system prompt"), "system prompt") { t.Fatal("expected marker removal") } }
