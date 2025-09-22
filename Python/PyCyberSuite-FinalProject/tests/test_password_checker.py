
import unittest
from modules.password_checker import strength_score

class TestPassword(unittest.TestCase):
    def test_strength(self):
        self.assertGreaterEqual(strength_score("Abcdef12!@"), 4)
        self.assertLessEqual(strength_score("abc"), 2)

if __name__ == "__main__":
    unittest.main()
