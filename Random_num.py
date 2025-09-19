import secrets
import string
def generate_random_string(length=16):
    # Define subset: digits + alphabets
    subset = string.ascii_letters + string.digits   # A-Z, a-z, 0-9
    
    # Generate random string using cryptographically secure RNG
    random_str = ''.join(secrets.choice(subset) for _ in range(length))
    
    return random_str
print("Random Key:", generate_random_string(16))