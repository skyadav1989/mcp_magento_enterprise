import secrets
import hashlib
import base64

# 1. Generate cryptographically secure code_verifier
code_verifier = secrets.token_urlsafe(64)

# 2. Generate S256 code_challenge
digest = hashlib.sha256(code_verifier.encode("ascii")).digest()

code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

print("CODE VERIFIER:")
print(code_verifier)

print("\nCODE CHALLENGE:")
print(code_challenge)

print("\nCODE CHALLENGE METHOD:")
print("S256")