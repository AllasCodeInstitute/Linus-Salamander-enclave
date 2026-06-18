package llm_1ntruder
import ("strings"; "testing")
func TestVulnerability(t *testing.T) { if !strings.Contains(vulnerable_scenario("x password="), "password=") { t.Fatal("expected vulnerable marker") } }
func TestDefense(t *testing.T) { if strings.Contains(LLM_1ntruder.Clean("Sensitive Information Disclosure", "x password="), "password=") { t.Fatal("expected marker removal") } }
