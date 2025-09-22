import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
import os
import socket
from modules.auth import AuthManager
from modules.network import NetworkScanner
from modules.subdomain import enumerate_subdomains
from modules.password_checker import PasswordChecker
from modules.brute_force import BruteForceSimulator
from modules.dict_attack import try_wordlist_against_hash
from modules.crypto_tools import SymmetricEncryption, AsymmetricEncryption
from modules.automation import AutomationModule
from modules.report import save_json_report

class CyberSuite:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PyCyberSuite - Red Hat Console")
        self.root.geometry("950x700")
        self.root.configure(bg="#1a1a1a")
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#1a1a1a', foreground='#e06c75', font=('Liberation Mono', 12))
        style.configure('TLabel', background='#1a1a1a', foreground='#e06c75', font=('Liberation Mono', 16, 'bold'))
        style.configure('TButton', background='#1a1a1a', foreground='#ffffff', font=('Liberation Mono', 13, 'bold'), borderwidth=2)
        style.map('TButton', background=[('active', '#3c3c3c'), ('pressed', '#3c3c3c')], foreground=[('active', '#e06c75')])
        style.configure('TEntry', fieldbackground='#282828', foreground='#e06c75', font=('Liberation Mono', 13))
        style.configure('TFrame', background='#1a1a1a')
        self.auth = AuthManager()
        self.show_login()
        self.root.mainloop()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_window()
        card = tk.Frame(self.root, bg="#232323", bd=0, highlightthickness=0)
        card.place(relx=0.5, rely=0.5, anchor="center", width=420, height=340)
        card.grid_propagate(False)
        # Rounded corners (simulate with padding and background)
        border = tk.Frame(card, bg="#e06c75", bd=0, highlightthickness=0)
        border.place(relx=0, rely=0, relwidth=1, relheight=1)
        inner = tk.Frame(card, bg="#232323", bd=0, highlightthickness=0)
        inner.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)
        title = tk.Label(inner, text="PyCyberSuite Login", fg="#e06c75", bg="#232323", font=("Liberation Mono", 20, "bold"))
        title.grid(row=0, columnspan=2, pady=(24, 18))
        tk.Label(inner, text="Username:", fg="#ffffff", bg="#232323", font=("Liberation Mono", 14)).grid(row=1, column=0, sticky="e", pady=8, padx=(0,10))
        self.username_entry = tk.Entry(inner, font=("Liberation Mono", 13), bg="#282828", fg="#e06c75", relief="flat", insertbackground="#e06c75")
        self.username_entry.grid(row=1, column=1, pady=8, padx=8)
        tk.Label(inner, text="Password:", fg="#ffffff", bg="#232323", font=("Liberation Mono", 14)).grid(row=2, column=0, sticky="e", pady=8, padx=(0,10))
        self.password_entry = tk.Entry(inner, show="*", font=("Liberation Mono", 13), bg="#282828", fg="#e06c75", relief="flat", insertbackground="#e06c75")
        self.password_entry.grid(row=2, column=1, pady=8, padx=8)
        btn_frame = tk.Frame(inner, bg="#232323")
        btn_frame.grid(row=3, columnspan=2, pady=22)
        login_btn = tk.Button(btn_frame, text="Login", command=self.attempt_login, font=("Liberation Mono", 13, "bold"), bg="#e06c75", fg="#fff", relief="flat", activebackground="#c43c3c", activeforeground="#fff", bd=0, padx=18, pady=6)
        login_btn.pack(side=tk.LEFT, padx=10)
        reg_btn = tk.Button(btn_frame, text="Register", command=self.show_register_dialog, font=("Liberation Mono", 13, "bold"), bg="#282828", fg="#e06c75", relief="flat", activebackground="#e06c75", activeforeground="#fff", bd=0, padx=18, pady=6)
        reg_btn.pack(side=tk.LEFT, padx=10)
        exit_btn = tk.Button(btn_frame, text="Exit", command=self.root.quit, font=("Liberation Mono", 13, "bold"), bg="#232323", fg="#fff", relief="flat", activebackground="#e06c75", activeforeground="#fff", bd=0, padx=18, pady=6)
        exit_btn.pack(side=tk.LEFT, padx=10)
        self.status_label = tk.Label(inner, text="", fg="#e06c75", bg="#232323", font=("Liberation Mono", 12, "italic"))
        self.status_label.grid(row=4, columnspan=2, pady=(10,0))
        self.username_entry.focus()

    def show_register_dialog(self):
        reg_win = tk.Toplevel(self.root)
        reg_win.title("Register - PyCyberSuite")
        reg_win.configure(bg="#101010")
        reg_win.geometry("340x200")
        reg_frame = ttk.Frame(reg_win, padding=20, style='TFrame')
        reg_frame.pack(expand=True)
        ttk.Label(reg_frame, text="Username:", style='TLabel').grid(row=0, column=0, sticky="e", pady=8)
        username_entry = ttk.Entry(reg_frame, style='TEntry')
        username_entry.grid(row=0, column=1, pady=8, padx=8)
        ttk.Label(reg_frame, text="Password:", style='TLabel').grid(row=1, column=0, sticky="e", pady=8)
        password_entry = ttk.Entry(reg_frame, show="*", style='TEntry')
        password_entry.grid(row=1, column=1, pady=8, padx=8)
        status_label = ttk.Label(reg_frame, text="", style='TLabel')
        status_label.grid(row=2, columnspan=2, pady=(10,0))
        def do_register():
            username = username_entry.get().strip()
            password = password_entry.get()
            if not username or not password:
                status_label.config(text="Both fields required!")
                return
            ok, msg = self.auth.register(username, password)
            if ok:
                status_label.config(text="Registration successful!")
                reg_win.after(1200, reg_win.destroy)
            else:
                status_label.config(text=f"Registration failed: {msg}")
        reg_btn = ttk.Button(reg_frame, text="Register", command=do_register, style='TButton')
        reg_btn.grid(row=3, column=0, columnspan=2, pady=12)

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.status_label.config(text="Both fields required!")
            return
        ok, msg = self.auth.login(username, password)
        if ok:
            self.status_label.config(text="Login successful! Welcome, {}.".format(username))
            self.root.after(800, self.show_main_menu)
        else:
            self.status_label.config(text=f"Login failed: {msg}")

    def show_main_menu(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=40, style='TFrame')
        frame.pack(expand=True)
        ttk.Label(frame, text="[ PyCyberSuite - Hacker Console ]", style='TLabel').pack(pady=(10, 30))
        divider = ttk.Separator(frame, orient='horizontal')
        divider.pack(fill=tk.X, padx=20, pady=(0, 30))
        menu_frame = ttk.Frame(frame, style='TFrame')
        menu_frame.pack(expand=True)
        tools = [
            ("Network Scanner", self.show_network_scanner),
            ("Subdomain Scanner", self.show_subdomain_scanner),
            ("Password Checker", self.show_password_checker),
            ("Encryption Tools", self.show_crypto_tools),
            ("Brute Force Simulator", self.show_brute_force),
            ("Dictionary Attack", self.show_dictionary_attack),
            ("Automation", self.show_automation),
            ("Reports/Logs", self.show_reports_logs),
        ]
        cols = 3
        for idx, (text, cmd) in enumerate(tools):
            row, col = divmod(idx, cols)
            btn = ttk.Button(menu_frame, text=text, command=cmd, style='TButton')
            btn.grid(row=row, column=col, padx=30, pady=18, sticky="ew")
        for c in range(cols):
            menu_frame.grid_columnconfigure(c, weight=1)
        ttk.Button(frame, text="Logout", command=self.show_login, style='TButton').pack(pady=18)

    def show_network_scanner(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Network Scanner", style='TLabel').pack(pady=10)
        input_frame = ttk.Frame(frame, style='TFrame')
        input_frame.pack(fill=tk.X, pady=10)
        try:
            hostname = socket.gethostname()
            system_ip = socket.gethostbyname(hostname)
        except Exception:
            system_ip = "127.0.0.1"
        ttk.Label(input_frame, text=f"System IP: {system_ip}", style='TLabel').pack(side=tk.LEFT)
        scan_btn = ttk.Button(frame, text="Scan", style='TButton', command=lambda: self.run_network_scan(system_ip))
        scan_btn.pack(pady=8)
        self.net_results = tk.Text(frame, height=16, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.net_results.pack(expand=True, fill=tk.BOTH, pady=8)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=18)

    def run_network_scan(self, target):
        self.net_results.delete(1.0, tk.END)
        self.net_results.insert(tk.END, f"Scanning {target} ...\n")
        def worker(target):
            try:
                scanner = NetworkScanner()
                results = scanner.quick_scan(target)
                save_path = save_json_report("network_scan", {"target": target, "results": results})
                self.net_results.insert(tk.END, f"Found {len(results)} live hosts. Report saved: {save_path}\n")
                for host, open_ports in results.items():
                    self.net_results.insert(tk.END, f"{host} -> open {open_ports}\n")
            except Exception as e:
                self.net_results.insert(tk.END, f"Error: {e}\n")
        Thread(target=worker, args=(target,), daemon=True).start()

    def show_subdomain_scanner(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Subdomain Scanner", style='TLabel').pack(pady=10)
        input_frame = ttk.Frame(frame, style='TFrame')
        input_frame.pack(fill=tk.X, pady=10)
        ttk.Label(input_frame, text="Domain:", style='TLabel').pack(side=tk.LEFT)
        self.subdomain_entry = ttk.Entry(input_frame, style='TEntry', width=30)
        self.subdomain_entry.pack(side=tk.LEFT, padx=8)
        self.subdomain_entry.insert(0, "example.com")
        ttk.Label(input_frame, text="Wordlist:", style='TLabel').pack(side=tk.LEFT, padx=8)
        self.subdomain_wordlist = ttk.Entry(input_frame, style='TEntry', width=30)
        self.subdomain_wordlist.pack(side=tk.LEFT, padx=8)
        self.subdomain_wordlist.insert(0, "data/subdomains.txt")
        scan_btn = ttk.Button(frame, text="Enumerate", style='TButton', command=self.run_subdomain_enum)
        scan_btn.pack(pady=8)
        self.subdomain_results = tk.Text(frame, height=16, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.subdomain_results.pack(expand=True, fill=tk.BOTH, pady=8)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=18)

    def run_subdomain_enum(self):
        domain = self.subdomain_entry.get().strip()
        wordlist = self.subdomain_wordlist.get().strip()
        if not domain or not wordlist:
            messagebox.showwarning("Error", "Please enter domain and wordlist.")
            return
        self.subdomain_results.delete(1.0, tk.END)
        self.subdomain_results.insert(tk.END, f"Enumerating subdomains for {domain} ...\n")
        def worker(domain, wordlist):
            try:
                res = enumerate_subdomains(domain, wordlist)
                save_path = save_json_report("subdomain_enum", {"domain": domain, "results": res})
                self.subdomain_results.insert(tk.END, f"Found {len(res)} subdomains. Report saved: {save_path}\n")
                for r in res:
                    self.subdomain_results.insert(tk.END, f"{r['subdomain']} -> {r['ip']}\n")
            except Exception as e:
                self.subdomain_results.insert(tk.END, f"Error: {e}\n")
        Thread(target=worker, args=(domain, wordlist), daemon=True).start()

    def show_password_checker(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Password Checker", style='TLabel').pack(pady=10)
        input_frame = ttk.Frame(frame, style='TFrame')
        input_frame.pack(fill=tk.X, pady=10)
        ttk.Label(input_frame, text="Password:", style='TLabel').pack(side=tk.LEFT)
        self.pw_entry = ttk.Entry(input_frame, style='TEntry', width=30, show="*")
        self.pw_entry.pack(side=tk.LEFT, padx=8)
        check_btn = ttk.Button(frame, text="Check", style='TButton', command=self.run_password_check)
        check_btn.pack(pady=8)
        self.pw_results = tk.Text(frame, height=10, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.pw_results.pack(expand=True, fill=tk.BOTH, pady=8)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=18)

    def run_password_check(self):
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showwarning("Error", "Please enter a password.")
            return
        checker = PasswordChecker(pw)
        complexity = checker.check_complexity()
        breach = checker.check_breach()
        self.pw_results.delete(1.0, tk.END)
        self.pw_results.insert(tk.END, f"Complexity: {complexity}\nBreach: {breach}\n")

    def show_crypto_tools(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Encryption Tools", style='TLabel').pack(pady=10)
        sym_frame = ttk.LabelFrame(frame, text="Symmetric Encryption (Fernet)", style='TFrame')
        sym_frame.pack(fill=tk.X, pady=8)
        if not hasattr(self, 'symmetric_crypto'):
            self.symmetric_crypto = SymmetricEncryption()
        ttk.Label(sym_frame, text="Message:", style='TLabel').pack(anchor=tk.W)
        self.sym_message = ttk.Entry(sym_frame, style='TEntry')
        self.sym_message.pack(fill=tk.X, pady=5)
        btn_frame = ttk.Frame(sym_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Encrypt", command=self.symmetric_encrypt, style='TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.symmetric_decrypt, style='TButton').pack(side=tk.LEFT, padx=5)
        self.sym_result = tk.Text(sym_frame, height=5, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.sym_result.pack(fill=tk.X)
        asym_frame = ttk.LabelFrame(frame, text="Asymmetric Encryption (RSA)", style='TFrame')
        asym_frame.pack(fill=tk.X, pady=8)
        if not hasattr(self, 'asymmetric_crypto'):
            self.asymmetric_crypto = AsymmetricEncryption()
        ttk.Label(asym_frame, text="Message:", style='TLabel').pack(anchor=tk.W)
        self.asym_message = ttk.Entry(asym_frame, style='TEntry')
        self.asym_message.pack(fill=tk.X, pady=5)
        btn_frame2 = ttk.Frame(asym_frame, style='TFrame')
        btn_frame2.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame2, text="Encrypt", command=self.asymmetric_encrypt, style='TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Decrypt", command=self.asymmetric_decrypt, style='TButton').pack(side=tk.LEFT, padx=5)
        self.asym_result = tk.Text(asym_frame, height=5, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.asym_result.pack(fill=tk.X)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=10)

    def symmetric_encrypt(self):
        message = self.sym_message.get()
        if not message:
            messagebox.showwarning("Error", "Please enter a message")
            return
        try:
            encrypted = self.symmetric_crypto.encrypt(message)
            self.sym_result.delete(1.0, tk.END)
            self.sym_result.insert(tk.END, f"Encrypted: {encrypted.decode()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def symmetric_decrypt(self):
        token = self.sym_result.get(1.0, tk.END).strip()
        if not token or not token.startswith("Encrypted: "):
            messagebox.showwarning("Error", "Nothing to decrypt")
            return
        try:
            token = token.replace("Encrypted: ", "")
            decrypted = self.symmetric_crypto.decrypt(token.encode())
            self.sym_result.insert(tk.END, f"\nDecrypted: {decrypted}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def asymmetric_encrypt(self):
        message = self.asym_message.get()
        if not message:
            messagebox.showwarning("Error", "Please enter a message")
            return
        try:
            encrypted = self.asymmetric_crypto.encrypt(message)
            self.asym_result.delete(1.0, tk.END)
            self.asym_result.insert(tk.END, f"Encrypted: {encrypted.hex()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def asymmetric_decrypt(self):
        token = self.asym_result.get(1.0, tk.END).strip()
        if not token or not token.startswith("Encrypted: "):
            messagebox.showwarning("Error", "Nothing to decrypt")
            return
        try:
            token = bytes.fromhex(token.replace("Encrypted: ", ""))
            decrypted = self.asymmetric_crypto.decrypt(token)
            self.asym_result.insert(tk.END, f"\nDecrypted: {decrypted}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_brute_force(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Brute Force Simulator", style='TLabel').pack(pady=10)
        input_frame = ttk.Frame(frame, style='TFrame')
        input_frame.pack(fill=tk.X, pady=10)
        ttk.Label(input_frame, text="Target Password:", style='TLabel').pack(side=tk.LEFT)
        self.bf_password_entry = ttk.Entry(input_frame, style='TEntry', width=20, show="*")
        self.bf_password_entry.pack(side=tk.LEFT, padx=8)
        ttk.Label(input_frame, text="Max Length:", style='TLabel').pack(side=tk.LEFT, padx=8)
        self.bf_max_length_entry = ttk.Spinbox(input_frame, from_=1, to=8, width=5)
        self.bf_max_length_entry.pack(side=tk.LEFT, padx=8)
        self.bf_max_length_entry.set(3)
        run_btn = ttk.Button(frame, text="Simulate Attack", style='TButton', command=self.run_brute_force_sim)
        run_btn.pack(pady=8)
        self.bf_results = tk.Text(frame, height=12, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.bf_results.pack(expand=True, fill=tk.BOTH, pady=8)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=18)

    def run_brute_force_sim(self):
        password = self.bf_password_entry.get().strip()
        try:
            max_length = int(self.bf_max_length_entry.get())
        except ValueError:
            messagebox.showwarning("Error", "Max length must be a number.")
            return
        if not password:
            messagebox.showwarning("Error", "Please enter a target password.")
            return
        self.bf_results.delete(1.0, tk.END)
        self.bf_results.insert(tk.END, f"Simulating brute force for password: {password} (max length {max_length})...\n")
        def worker(password, max_length):
            try:
                sim = BruteForceSimulator(password, max_length)
                found, attempts = sim.simulate()
                report = {
                    "password": password,
                    "max_length": max_length,
                    "found": bool(found),
                    "attempts": attempts,
                    "result": found if found else None
                }
                save_path = save_json_report("bruteforce_sim", report)
                if found:
                    self.bf_results.insert(tk.END, f"Password found in {attempts} attempts: {found}\n")
                else:
                    self.bf_results.insert(tk.END, "Password NOT found.\n")
                self.bf_results.insert(tk.END, f"Report saved: {save_path}\n")
            except Exception as e:
                self.bf_results.insert(tk.END, f"Error: {e}\n")
        Thread(target=worker, args=(password, max_length), daemon=True).start()

    def show_dictionary_attack(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Dictionary Attack", style='TLabel').pack(pady=10)
        input_frame = ttk.Frame(frame, style='TFrame')
        input_frame.pack(fill=tk.X, pady=10)
        ttk.Label(input_frame, text="Target Hash (sha256):", style='TLabel').pack(side=tk.LEFT)
        self.dict_hash_entry = ttk.Entry(input_frame, style='TEntry', width=40)
        self.dict_hash_entry.pack(side=tk.LEFT, padx=8)
        ttk.Label(input_frame, text="Wordlist:", style='TLabel').pack(side=tk.LEFT, padx=8)
        self.dict_wordlist_entry = ttk.Entry(input_frame, style='TEntry', width=30)
        self.dict_wordlist_entry.pack(side=tk.LEFT, padx=8)
        self.dict_wordlist_entry.insert(0, "data/passwords.txt")
        run_btn = ttk.Button(frame, text="Run", style='TButton', command=self.run_dict_attack)
        run_btn.pack(pady=8)
        self.dict_results = tk.Text(frame, height=10, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.dict_results.pack(expand=True, fill=tk.BOTH, pady=8)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=18)

    def run_dict_attack(self):
        hashval = self.dict_hash_entry.get().strip()
        wordlist = self.dict_wordlist_entry.get().strip()
        self.dict_results.delete(1.0, tk.END)
        self.dict_results.insert(tk.END, f"Running dictionary attack...\n")
        res = try_wordlist_against_hash(hashval, wordlist)
        save_path = save_json_report("dictionary_attack", res)
        if res["match"]:
            self.dict_results.insert(tk.END, f"PASSWORD FOUND: {res['password']}\n")
        else:
            self.dict_results.insert(tk.END, "No match in wordlist.\n")
        self.dict_results.insert(tk.END, f"Report saved: {save_path}\n")

    def show_main_menu(self):
        self.clear_window()
        card = tk.Frame(self.root, bg="#232323", bd=0, highlightthickness=0)
        card.place(relx=0.5, rely=0.5, anchor="center", width=700, height=420)
        card.grid_propagate(False)
        border = tk.Frame(card, bg="#e06c75", bd=0, highlightthickness=0)
        border.place(relx=0, rely=0, relwidth=1, relheight=1)
        inner = tk.Frame(card, bg="#232323", bd=0, highlightthickness=0)
        inner.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)
        title = tk.Label(inner, text="PyCyberSuite Toolkit", fg="#e06c75", bg="#232323", font=("Liberation Mono", 20, "bold"))
        title.pack(pady=(18, 18))
        divider = tk.Frame(inner, bg="#e06c75", height=2)
        divider.pack(fill=tk.X, padx=20, pady=(0, 18))
        tools = [
            ("Network Scanner", self.show_network_scanner),
            ("Subdomain Scanner", self.show_subdomain_scanner),
            ("Password Checker", self.show_password_checker),
            ("Encryption Tools", self.show_crypto_tools),
            ("Brute Force Simulator", self.show_brute_force),
            ("Dictionary Attack", self.show_dictionary_attack),
            ("Automation", self.show_automation),
            ("Reports", self.show_reports_logs)
        ]
        rows = 2
        cols = 4
        grid_frame = tk.Frame(inner, bg="#232323")
        grid_frame.pack(expand=True)
        for i, (label, cmd) in enumerate(tools):
            r, c = divmod(i, cols)
            btn = tk.Button(grid_frame, text=label, command=cmd, font=("Liberation Mono", 13, "bold"), bg="#e06c75", fg="#fff", relief="flat", activebackground="#c43c3c", activeforeground="#fff", bd=0, padx=18, pady=12, wraplength=140, justify="center")
            btn.grid(row=r, column=c, padx=18, pady=18, sticky="nsew")
        for c in range(cols):
            grid_frame.grid_columnconfigure(c, weight=1)
        back_btn = tk.Button(inner, text="Logout", command=self.show_login, font=("Liberation Mono", 13, "bold"), bg="#232323", fg="#fff", relief="flat", activebackground="#e06c75", activeforeground="#fff", bd=0, padx=18, pady=8)
        back_btn.pack(pady=(18, 0))
        # ...existing code...

    def show_automation(self):
        self.clear_window()
        import socket
        system_ip = socket.gethostbyname(socket.gethostname())
        card = tk.Frame(self.root, bg="#232323", bd=0, highlightthickness=0)
        card.place(relx=0.5, rely=0.5, anchor="center", width=900, height=600)
        card.grid_propagate(False)
        border = tk.Frame(card, bg="#e06c75", bd=0, highlightthickness=0)
        border.place(relx=0, rely=0, relwidth=1, relheight=1)
        inner = tk.Frame(card, bg="#232323", bd=0, highlightthickness=0)
        inner.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)
        title = tk.Label(inner, text="Automation Module", fg="#e06c75", bg="#232323", font=("Liberation Mono", 20, "bold"))
        title.pack(pady=(18, 18))
        divider = tk.Frame(inner, bg="#e06c75", height=2)
        divider.pack(fill=tk.X, padx=20, pady=(0, 18))
        form = tk.Frame(inner, bg="#232323")
        form.pack(pady=8)
        tk.Label(form, text="Network Scan Interval (min):", fg="#fff", bg="#232323", font=("Liberation Mono", 13)).grid(row=0, column=0, sticky="e", padx=(0,10), pady=6)
        self.auto_net_time_entry = tk.Entry(form, font=("Liberation Mono", 13), bg="#282828", fg="#e06c75", relief="flat", width=8)
        self.auto_net_time_entry.grid(row=0, column=1, padx=8, pady=6)
        tk.Label(form, text="Password Check Interval (min):", fg="#fff", bg="#232323", font=("Liberation Mono", 13)).grid(row=1, column=0, sticky="e", padx=(0,10), pady=6)
        self.auto_pw_time_entry = tk.Entry(form, font=("Liberation Mono", 13), bg="#282828", fg="#e06c75", relief="flat", width=8)
        self.auto_pw_time_entry.grid(row=1, column=1, padx=8, pady=6)
        tk.Label(form, text="Password to Check:", fg="#fff", bg="#232323", font=("Liberation Mono", 13)).grid(row=2, column=0, sticky="e", padx=(0,10), pady=6)
        self.auto_pw_entry = tk.Entry(form, font=("Liberation Mono", 13), bg="#282828", fg="#e06c75", relief="flat", width=18)
        self.auto_pw_entry.grid(row=2, column=1, padx=8, pady=6)
        self.auto_results = tk.Text(inner, font=("Liberation Mono", 12), bg="#232323", fg="#fff", relief="flat", height=7, bd=0)
        self.auto_results.pack(expand=True, fill=tk.BOTH, pady=8)
        btn_frame = tk.Frame(inner, bg="#232323")
        btn_frame.pack(pady=8)
        start_btn = tk.Button(btn_frame, text="Start Automation", font=("Liberation Mono", 13, "bold"), bg="#e06c75", fg="#fff", relief="flat", activebackground="#c43c3c", activeforeground="#fff", bd=0, padx=18, pady=6, command=lambda: self.run_automation(system_ip))
        start_btn.pack(side=tk.LEFT, padx=10)
        stop_btn = tk.Button(btn_frame, text="Stop Automation", font=("Liberation Mono", 13, "bold"), bg="#282828", fg="#e06c75", relief="flat", activebackground="#e06c75", activeforeground="#fff", bd=0, padx=18, pady=6, command=self.stop_automation)
        stop_btn.pack(side=tk.LEFT, padx=10)
        back_btn = tk.Button(btn_frame, text="Back to Menu", font=("Liberation Mono", 13, "bold"), bg="#232323", fg="#fff", relief="flat", activebackground="#e06c75", activeforeground="#fff", bd=0, padx=18, pady=8, command=self.show_main_menu)
        back_btn.pack(side=tk.LEFT, padx=10)

    def run_automation(self, system_ip):
        net_time = self.auto_net_time_entry.get().strip()
        pw_time = self.auto_pw_time_entry.get().strip()
        password = self.auto_pw_entry.get().strip()
        self.auto_results.insert(tk.END, f"[*] Starting automation module...\n")
        def worker():
            try:
                import schedule
                schedule.clear()
                # Network scan automation with result display
                def net_scan_job():
                    try:
                        scanner = NetworkScanner()
                        results = scanner.quick_scan(system_ip)
                        self.auto_results.insert(tk.END, f"[Network Scan] Found {len(results)} live hosts.\n")
                        for host, open_ports in results.items():
                            self.auto_results.insert(tk.END, f"{host} -> open {open_ports}\n")
                    except Exception as e:
                        self.auto_results.insert(tk.END, f"[Network Scan] Error: {e}\n")
                schedule.every().day.at(net_time).do(net_scan_job)
                # Password check automation with breach display
                if password:
                    def pw_check_job():
                        try:
                            checker = PasswordChecker(password)
                            complexity = checker.check_complexity()
                            breach = checker.check_breach()
                            self.auto_results.insert(tk.END, f"[Password Check] {complexity} | Breach: {breach}\n")
                        except Exception as e:
                            self.auto_results.insert(tk.END, f"[Password Check] Error: {e}\n")
                    schedule.every().day.at(pw_time).do(pw_check_job)
                self.auto_results.insert(tk.END, f"[*] Automation tasks scheduled.\n")
                while True:
                    schedule.run_pending()
                    import time
                    time.sleep(1)
            except Exception as e:
                self.auto_results.insert(tk.END, f"Error: {e}\n")
        Thread(target=worker, daemon=True).start()

    def stop_automation(self):
        try:
            import schedule
            schedule.clear()
            self.auto_results.insert(tk.END, "[*] Automation stopped.\n")
        except Exception as e:
            self.auto_results.insert(tk.END, f"Error stopping automation: {e}\n")

    def show_reports_logs(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding=30, style='TFrame')
        frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(frame, text="Reports/Logs", style='TLabel').pack(pady=10)
        self.reports_results = tk.Text(frame, height=16, bg="#222", fg="#39ff14", font=("Consolas", 12))
        self.reports_results.pack(expand=True, fill=tk.BOTH, pady=8)
        ttk.Button(frame, text="Refresh", style='TButton', command=self.refresh_reports).pack(pady=8)
        ttk.Button(frame, text="Back to Menu", command=self.show_main_menu, style='TButton').pack(pady=18)

    def refresh_reports(self):
        rep_dir = os.path.join(os.path.dirname(__file__), "reports")
        self.reports_results.delete(1.0, tk.END)
        self.reports_results.insert(tk.END, "--- Reports ---\n")
        if not os.path.exists(rep_dir):
            self.reports_results.insert(tk.END, "No reports found.\n")
            return
        for name in sorted(os.listdir(rep_dir)):
            self.reports_results.insert(tk.END, os.path.join("reports", name) + "\n")

if __name__ == "__main__":
    CyberSuite()
