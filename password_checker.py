import re
import requests
import math
import hashlib

def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[^A-Za-z0-9]', password):
        pool += 32  # Approximate number of printable symbols
    if pool == 0:
        return 0
    entropy = len(password) * math.log2(pool)
    return entropy

def check_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return None  # API error
        hashes = (line.split(':') for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return None  # Network error

def check_password_strength(password):
    requirements = {
        'min_length': len(password) >= 8,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'digit': bool(re.search(r'\d', password)),
        'symbol': bool(re.search(r'[^A-Za-z0-9]', password))
    }

    print("Password requirements:")
    for req, met in requirements.items():
        print(f" - {req.replace('_', ' ').capitalize()}: {'OK' if met else 'Missing'}")

    entropy = calculate_entropy(password)
    print(f"\nEstimated entropy: {entropy:.1f} bits")
    if entropy < 40:
        print(" - Entropy strength: Very Weak")
    elif entropy < 60:
        print(" - Entropy strength: Weak")
    elif entropy < 80:
        print(" - Entropy strength: Moderate")
    elif entropy < 100:
        print(" - Entropy strength: Strong")
    else:
        print(" - Entropy strength: Very Strong")

    # Only check pwned if basic requirements are met
    if all(requirements.values()):
        print("\nChecking against HaveIBeenPwned...")
        count = check_pwned(password)
        if count is None:
            print(" - Could not check password leak status (API/network error).")
        elif count == 0:
            print(" - This password was NOT found in known data breaches.")
        else:
            print(f" - WARNING: This password has been found {count} times in data breaches!")
    else:
        print("\nPassword does not meet all basic requirements. Skipping leak check.")


import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

def gui_mode():
    def on_check():
        entered_pw = entry.get()
        if not entered_pw:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return
        output.delete(1.0, tk.END)
        # Capture print output
        import io
        import sys
        buf = io.StringIO()
        sys_stdout = sys.stdout
        sys.stdout = buf
        check_password_strength(entered_pw)
        sys.stdout = sys_stdout
        output.insert(tk.END, buf.getvalue())

    root = tk.Tk()
    root.title("Password Strength Checker")
    root.geometry("500x400")

    ttk.Label(root, text="Enter Password:").pack(pady=(10, 0))
    entry = ttk.Entry(root, show='*', width=40)
    entry.pack(pady=5)
    ttk.Button(root, text="Check", command=on_check).pack(pady=5)
    output = tk.Text(root, height=18, width=60)
    output.pack(pady=10)
    root.mainloop()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'gui':
        gui_mode()
    else:
        pw = input("Enter a password to check: ")
        check_password_strength(pw)
