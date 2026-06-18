import unittest
from vulnerable import vulnerable_scenario
from lib import LLM_1ntruder
class SecurityTest(unittest.TestCase):
 def test_vulnerability(self): self.assertIn("<script", vulnerable_scenario("x <script"))
 def test_defense(self): self.assertNotIn("<script", LLM_1ntruder.clean("Improper Output Handling", "x <script"))
if __name__ == "__main__": unittest.main()
