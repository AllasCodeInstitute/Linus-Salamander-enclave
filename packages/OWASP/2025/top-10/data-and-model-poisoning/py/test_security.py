import unittest
from vulnerable import vulnerable_scenario
from lib import LLM_1ntruder
class SecurityTest(unittest.TestCase):
 def test_vulnerability(self): self.assertIn("backdoor", vulnerable_scenario("x backdoor"))
 def test_defense(self): self.assertNotIn("backdoor", LLM_1ntruder.clean("Data and Model Poisoning", "x backdoor"))
if __name__ == "__main__": unittest.main()
