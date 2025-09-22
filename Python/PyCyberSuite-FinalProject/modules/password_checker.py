"""
This module provides the PasswordChecker class for evaluating password strength and checking for breaches.
It checks complexity and queries breach databases to see if a password has been compromised.
Used for password security analysis in CyberSuite.
"""
import re        # For regular expressions (complexity checks)
import hashlib   # For hashing passwords
import requests  # For making HTTP requests to breach API

class PasswordChecker:
    def __init__(self, password):
        # Store the password to check
        self.password = password

    def check_complexity(self):
        """
        Checks the complexity of the password and returns a message about its strength.
        """
        if len(self.password) < 8:
            return "Weak: Password too short"
        if not re.search(r"[A-Z]", self.password):
            return "Weak: Missing uppercase letter"
        if not re.search(r"[a-z]", self.password):
            return "Weak: Missing lowercase letter"
        if not re.search(r"\d", self.password):
            return "Weak: Missing number"
        if not re.search(r"[!@#$%^&*]", self.password):
            return "Weak: Missing special character"
        return "Strong password"
    
    def check_breach(self):
        """
        Checks if the password has been found in known breaches using the Pwned Passwords API.
        """
        # Hash the password using SHA-1 and split into prefix/suffix
        sha1 = hashlib.sha1(self.password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            # Query the API for breached passwords with the same prefix
            response = requests.get(url)
            if response.status_code != 200:
                return "Error: Could not check breach"
            # Check if the suffix matches any returned hash
            for line in response.text.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    hash_suffix, count = parts[0], parts[1]
                    if hash_suffix == suffix:
                        return f"Found in breaches {count} times!"
            return "Not found in breaches"
        except Exception as e:
            return f"Error: {str(e)}"