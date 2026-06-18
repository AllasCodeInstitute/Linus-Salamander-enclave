import unittest
from vulnerable import vulnerable_scenario
from lib import LLM_1ntruder
class SecurityTest(unittest.TestCase):
 def test_vulnerability(self): self.assertIn("http://", vulnerable_scenario("x http://"))
 def test_defense(self): self.assertNotIn("http://", LLM_1ntruder.clean("Supply Chain Vulnerabilities", "x http://"))
if __name__ == "__main__": unittest.main()
