
import socket
from .utils import timestamp

def resolve_subdomain(sub: str, domain: str):
    fqdn = f"{sub}.{domain}".strip(".")
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip, "time": timestamp()}
    except socket.gaierror:
        return None

def enumerate_subdomains(domain: str, wordlist_path: str):
    results = []
    with open(wordlist_path, "r", encoding="utf-8") as f:
        for line in f:
            sub = line.strip()
            if not sub: 
                continue
            res = resolve_subdomain(sub, domain)
            if res:
                results.append(res)
    return results
