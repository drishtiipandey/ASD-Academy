"""
This module provides a BruteForceSimulator class that tries to guess a target password by generating all possible combinations of lowercase letters and digits up to a specified length.
It counts the number of attempts and returns the password if found, or None if not found.
Useful for demonstrating brute force attacks and password strength.
"""
import itertools  # For generating combinations
import string  # For character sets

class BruteForceSimulator:
    def __init__(self, password, max_length=3):
        """
        Initialize the simulator with a target password and maximum guess length.
        :param password: The password to guess.
        :param max_length: The maximum length of guesses to try.
        """
        self.password = password  # Store the target password
        self.length = max_length  # Store the maximum guess length

    def simulate(self):
        """
        Attempt to brute force the password by trying all combinations up to max_length.
        Returns the found password and number of attempts, or None if not found.
        """
        characters = string.ascii_lowercase + string.digits  # Allowed characters
        attempts = 0  # Counter for number of attempts
        # Try all possible combinations for each length
        for length in range(1, self.length + 1):
            for guess in itertools.product(characters, repeat=length):
                attempts += 1  # Increment attempt counter
                attempt = "".join(guess)  # Build the guess string
                if attempt == self.password:
                    return attempt, attempts  # Return if password is found
        # If not found, return None and total attempts
        return None, attempts