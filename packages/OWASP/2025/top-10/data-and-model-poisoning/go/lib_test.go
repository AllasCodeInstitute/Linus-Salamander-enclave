package llm_1ntruder
import ("strings"; "testing")
func TestVulnerability(t *testing.T) { if !strings.Contains(vulnerable_scenario("x backdoor"), "backdoor") { t.Fatal("expected vulnerable marker") } }
func TestDefense(t *testing.T) { if strings.Contains(LLM_1ntruder.Clean("Data and Model Poisoning", "x backdoor"), "backdoor") { t.Fatal("expected marker removal") } }
