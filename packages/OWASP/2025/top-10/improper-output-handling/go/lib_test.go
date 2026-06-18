package llm_1ntruder
import ("strings"; "testing")
func TestVulnerability(t *testing.T) { if !strings.Contains(vulnerable_scenario("x <script"), "<script") { t.Fatal("expected vulnerable marker") } }
func TestDefense(t *testing.T) { if strings.Contains(LLM_1ntruder.Clean("Improper Output Handling", "x <script"), "<script") { t.Fatal("expected marker removal") } }
