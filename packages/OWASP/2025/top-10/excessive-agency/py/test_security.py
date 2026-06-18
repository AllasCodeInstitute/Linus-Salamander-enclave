import unittest
from vulnerable import vulnerable_scenario
from lib import LLM_1ntruder
class SecurityTest(unittest.TestCase):
 def test_vulnerability(self): self.assertIn("delete all", vulnerable_scenario("x delete all"))
 def test_defense(self): self.assertNotIn("delete all", LLM_1ntruder.clean("Excessive Agency", "x delete all"))
if __name__ == "__main__": unittest.main()
