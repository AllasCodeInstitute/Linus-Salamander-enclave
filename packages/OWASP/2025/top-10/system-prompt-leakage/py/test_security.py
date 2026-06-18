import unittest
from vulnerable import vulnerable_scenario
from lib import LLM_1ntruder
class SecurityTest(unittest.TestCase):
 def test_vulnerability(self): self.assertIn("system prompt", vulnerable_scenario("x system prompt"))
 def test_defense(self): self.assertNotIn("system prompt", LLM_1ntruder.clean("System Prompt Leakage", "x system prompt"))
if __name__ == "__main__": unittest.main()
