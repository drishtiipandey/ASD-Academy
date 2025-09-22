
import unittest, os, json
from modules.auth import AuthManager

class TestAuth(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(os.path.dirname(__file__), "..", "data", "test_users.json")
        if os.path.exists(self.db):
            os.remove(self.db)
        self.auth = AuthManager(self.db)

    def test_register_and_login(self):
        ok, msg = self.auth.register("alice", "Str0ng@Pass")
        self.assertTrue(ok)
        ok, msg = self.auth.login("alice", "Str0ng@Pass")
        self.assertTrue(ok)
        ok, msg = self.auth.login("alice", "wrong")
        self.assertFalse(ok)

if __name__ == "__main__":
    unittest.main()
