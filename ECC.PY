class ECC:
    def __init__(self, p, a, b, G, n):
        self.p = p      # prime number (field size)
        self.a = a      # curve parameter a
        self.b = b      # curve parameter b
        self.G = G      # base point (x,y)
        self.n = n      # order of base point

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P == Q:
            # Point doubling
            lam = (3 * P[0]*P[0] + self.a) * self.inv_mod(2*P[1], self.p) % self.p
        else:
            if P[0] == Q[0] and (P[1] + Q[1]) % self.p == 0:
                return None  # Point at infinity
            lam = (Q[1] - P[1]) * self.inv_mod(Q[0] - P[0], self.p) % self.p

        x_r = (lam*lam - P[0] - Q[0]) % self.p
        y_r = (lam*(P[0] - x_r) - P[1]) % self.p
        return (x_r, y_r)

    def scalar_mult(self, k, P):
        R = None
        addend = P

        while k > 0:
            if k & 1:
                R = self.point_add(R, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return R

    def inv_mod(self, k, p):
        # Modular inverse via Extended Euclidean algorithm
        if k == 0:
            raise ZeroDivisionError('division by zero')
        if k < 0:
            return p - self.inv_mod(-k, p)
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, k
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient*r
            old_s, s = s, old_s - quotient*s
            old_t, t = t, old_t - quotient*t
        gcd, x, y = old_r, old_s, old_t
        assert gcd == 1
        return x % p

    def generate_keypair(self, private_key):
        # Public key Q = d * G
        if not (1 <= private_key < self.n):
            raise ValueError("Invalid private key")
        public_key = self.scalar_mult(private_key, self.G)
        return public_key

    def encrypt(self, M, public_key, k):
        # M is a point on curve (plaintext)
        C1 = self.scalar_mult(k, self.G)
        S = self.scalar_mult(k, public_key)
        C2 = ( (M[0] + S[0]) % self.p, (M[1] + S[1]) % self.p )
        return C1, C2

    def decrypt(self, C1, C2, private_key):
        S = self.scalar_mult(private_key, C1)
        M = ( (C2[0] - S[0]) % self.p, (C2[1] - S[1]) % self.p )
        return M

# Example parameters for a small curve:
p = 9739
a = 497
b = 1768
G = (1804, 5368)
n = 9929  # order of G

ecc = ECC(p, a, b, G, n)

# Alice's private key:
d = 1829
Q = ecc.generate_keypair(d)  # public key

# Message point M (must lie on the curve)
M = (815, 3190)

# Bob encrypts message for Alice with random k
k = 1234
C1, C2 = ecc.encrypt(M, Q, k)

# Alice decrypts
decrypted_M = ecc.decrypt(C1, C2, d)

print("Original message point:", M)
print("Encrypted points: C1 =", C1, "C2 =", C2)
print("Decrypted message point:", decrypted_M)
