
import hashlib
from .utils import timestamp

def try_wordlist_against_hash(target_hash: str, wordlist_path: str, algo="sha256"):
    h = getattr(hashlib, algo.lower())
    with open(wordlist_path, "r", encoding="utf-8") as f:
        for line in f:
            pwd = line.strip()
            if not pwd:
                continue
            if h(pwd.encode()).hexdigest() == target_hash.lower():
                return {"match": True, "password": pwd, "time": timestamp()}
    return {"match": False, "time": timestamp()}
