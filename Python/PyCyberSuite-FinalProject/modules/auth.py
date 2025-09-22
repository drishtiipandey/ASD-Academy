
from __future__ import annotations
import os, json, bcrypt, getpass
from .utils import read_json, write_json, timestamp

USERS_DB = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "users.json")

class AuthManager:
    def __init__(self, db_path: str = USERS_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        if not os.path.exists(self.db_path):
            write_json(self.db_path, {"users":[]})

    def _load(self):
        return read_json(self.db_path, {"users":[]})

    def _save(self, data):
        write_json(self.db_path, data)

    def _find_user(self, username: str):
        db = self._load()
        for u in db["users"]:
            if u["username"].lower() == username.lower():
                return u
        return None

    def register(self, username: str, password: str):
        if self._find_user(username):
            return False, "User already exists"
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt).decode()
        db = self._load()
        db["users"].append({"username": username, "password": hashed, "created_at": timestamp()})
        self._save(db)
        return True, "Registration successful"

    def login(self, username: str, password: str):
        u = self._find_user(username)
        if not u:
            return False, "User not found"
        if bcrypt.checkpw(password.encode(), u["password"].encode()):
            return True, "Login successful"
        return False, "Invalid password"
