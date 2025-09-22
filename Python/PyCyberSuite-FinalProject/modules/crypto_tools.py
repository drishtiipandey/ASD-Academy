"""
This module provides classes for symmetric and asymmetric encryption.
SymmetricEncryption uses a secret key for encrypting and decrypting messages.
AsymmetricEncryption uses public/private key pairs for secure communication.
Used for protecting sensitive data in CyberSuite.
"""
from cryptography.fernet import Fernet  # For symmetric encryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # For asymmetric encryption
from cryptography.hazmat.primitives import hashes  # For hashing in encryption

class SymmetricEncryption:
    def __init__(self):
        # Generate a secret key for symmetric encryption
        self.key = Fernet.generate_key()
        # Create a Fernet cipher object using the key
        self.cipher = Fernet(self.key)
    
    def encrypt(self, message: str) -> bytes:
        # Encrypt the message using the cipher and return bytes
        return self.cipher.encrypt(message.encode())
    
    def decrypt(self, token: bytes) -> str:
        # Decrypt the token and return the original message as a string
        return self.cipher.decrypt(token).decode()
    
class AsymmetricEncryption:
    def __init__(self):
        # Generate RSA private and public keys for asymmetric encryption
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def encrypt(self, message: str) -> bytes:
        # Encrypt the message using the public key
        if isinstance(message, str):
            message = message.encode()
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext: bytes) -> str:
        # Decrypt the ciphertext using the private key and return as string
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()