
# PyCyberSuite – All-in-One Cybersecurity Toolkit

A modular, GUI-based cybersecurity toolkit built with **Python 3** and **Tkinter**.

## Features
- **User Authentication** with hashed+salted passwords (bcrypt)
- **Network Scanner** (TCP connect scan of common ports, threaded)
- **Subdomain Enumerator** (wordlist + DNS resolve)
- **Password Strength Checker** + **HaveIBeenPwned** k-anonymity breach check
- **Brute Force Simulator** (test account against wordlist)
- **Dictionary Attack Tool** (hash -> wordlist)
- **Encryption/Decryption** (Fernet symmetric, RSA asymmetric)
- **Automation** (daily scheduled jobs to JSON reports)
- **Report Generator** (.json/.log outputs)
- **Unit Tests** for 3 modules

## Project Structure
```
PyCyberSuite/
  main.py
  modules/
    auth.py, network.py, subdomain.py, password_checker.py,
    brute_force.py, dict_attack.py, crypto_tools.py,
    automation.py, report.py, utils.py
  tests/
    test_auth.py, test_crypto.py, test_password_checker.py
  data/
    subdomains.txt, passwords.txt, users.json
  reports/, logs/
```

## Installation
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

## Run
```bash
python main.py
```

## Unit Tests
```bash
python -m unittest discover -s tests -v
```

## Notes
- HIBP API is public, internet required for breach count.
- Network scan uses TCP connect; running as admin is **not** required.
- Treat this toolkit as **educational** and use only on systems you own or are authorized to test.
