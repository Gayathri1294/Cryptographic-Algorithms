p = 23  # prime number
g = 5   # primitive root modulo p
print("Publicly Shared Values:")
print(f"Prime number (p): {p}")
print(f"Primitive root (g): {g}")
# Step 2: Private keys (chosen secretly by Alice and Bob)
a = 6   # Alice's private key
b = 15  # Bob's private key
print("\nPrivate Keys:")
print(f"Alice's Private Key (a): {a}")
print(f"Bob's Private Key (b): {b}")
# Step 3: Compute public keys to exchange
A = (g ** a) % p  # Alice's public key
B = (g ** b) % p  # Bob's public key
print("\nPublic Keys Exchanged:")
print(f"Alice sends Public Key (A): {A}")
print(f"Bob sends Public Key (B): {B}")
# Step 4: Each computes the shared secret key
secret_key_A = pow(B, a, p)  # Alice computes
secret_key_B = pow(A, b, p)  # Bob computes
print("\nShared Secret Key Computation:")
print(f"Alice's Computed Secret Key: {secret_key_A}")
print(f"Bob's Computed Secret Key: {secret_key_B}")
# Step 5: Verify if keys match
if secret_key_A == secret_key_B:
    print(f"\n Shared Secret Key Established Successfully: {secret_key_A}")
else:
    print("\n Shared Secret Key Mismatch! Possible error or tampering detected.")
