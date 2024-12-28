import getpass
import re

def is_strong_password(password):
    # Check if password meets strength criteria (at least 8 characters, includes letters and numbers)
    if len(password) >= 8 and re.search(r"[A-Za-z]", password) and re.search(r"\d", password):
        return True
    return False

attempts = 0
max_attempts = 5
invalid_attempts = []

while attempts < max_attempts:
    enc = getpass.getpass('Insert encrypted password: ')
    attempts += 1

    if len(enc) < 3:
        print("Error: Password too short. Please provide a valid encrypted password.")
        invalid_attempts.append(enc)
        continue

    c = enc.split(':')[3] if ':' in enc else enc
    cl = len(c)
    pad = (int)((cl / 4) - 36)
    pad1 = 1 if c[-1] == '=' else 0
    pad2 = 1 if c[-2] == '=' else 0
    pl = (len(c) - 136 - pad - pad1 - pad2)

    if pl < 0:
        print("Error: Invalid encrypted password format.")
        invalid_attempts.append(enc)
    else:        
        print("Password length: " + str(pl))
        if is_strong_password(c):
            print("Password strength: Strong")
        else:
            print("Password strength: Weak")
        break
else:
    print("Error: Too many invalid attempts. Please try again later.")

# Log invalid attempts
if invalid_attempts:
    print("Invalid attempts were logged for review.")
