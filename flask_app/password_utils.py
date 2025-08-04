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
        pool += 32
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
            return None
        hashes = (line.split(':') for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return None

def check_password_strength_web(password):
    requirements = {
        'Minimum length (8+)': len(password) >= 8,
        'Uppercase': bool(re.search(r'[A-Z]', password)),
        'Lowercase': bool(re.search(r'[a-z]', password)),
        'Digit': bool(re.search(r'\d', password)),
        'Symbol': bool(re.search(r'[^A-Za-z0-9]', password))
    }

    entropy = calculate_entropy(password)
    if entropy < 40:
        entropy_level = "Very Weak"
    elif entropy < 60:
        entropy_level = "Weak"
    elif entropy < 80:
        entropy_level = "Moderate"
    elif entropy < 100:
        entropy_level = "Strong"
    else:
        entropy_level = "Very Strong"

    pwned_count = None
    if all(requirements.values()):
        pwned_count = check_pwned(password)
    return {
        'requirements': requirements,
        'entropy': entropy,
        'entropy_level': entropy_level,
        'pwned_count': pwned_count
    }
