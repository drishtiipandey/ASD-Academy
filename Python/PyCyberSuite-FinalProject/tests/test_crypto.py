
import unittest
from modules.crypto_tools import generate_fernet_key, fernet_encrypt, fernet_decrypt

class TestCrypto(unittest.TestCase):
    def test_fernet_roundtrip(self):
        key = generate_fernet_key()
        pt = b"hello world"
        ct = fernet_encrypt(key, pt)
        rt = fernet_decrypt(key, ct)
        self.assertEqual(pt, rt)

if __name__ == "__main__":
    unittest.main()
