package llm_1ntruder
import ("strings"; "testing")
func TestVulnerability(t *testing.T) { if !strings.Contains(vulnerable_scenario("x delete all"), "delete all") { t.Fatal("expected vulnerable marker") } }
func TestDefense(t *testing.T) { if strings.Contains(LLM_1ntruder.Clean("Excessive Agency", "x delete all"), "delete all") { t.Fatal("expected marker removal") } }
