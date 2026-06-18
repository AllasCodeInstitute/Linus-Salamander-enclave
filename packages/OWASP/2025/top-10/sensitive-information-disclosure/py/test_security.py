import unittest
from vulnerable import vulnerable_scenario
from lib import LLM_1ntruder
class SecurityTest(unittest.TestCase):
 def test_vulnerability(self): self.assertIn("password=", vulnerable_scenario("x password="))
 def test_defense(self): self.assertNotIn("password=", LLM_1ntruder.clean("Sensitive Information Disclosure", "x password="))
if __name__ == "__main__": unittest.main()
