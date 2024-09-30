import galois


def from_roots(roots, field):
    roots = [field(r) for r in roots]
    N = len(roots)
    coefs = [field(0)] * (N + 1)
    coefs[0] = -roots[0]
    coefs[1] = field(1)

    for k in range(2, N + 1):
        coefs[k] = field(1)
        for i in range(k - 2, -1, -1):
            coefs[i + 1] = coefs[i] - roots[k - 1] * coefs[i + 1]
        coefs[0] *= -roots[k - 1]

    coefs.reverse()
    return coefs

def from_roots2(roots, field):
    roots = [field(r) for r in roots]
    N = len(roots)
    coefs = [field(1)] + [field(0)] * N  # Initialize [1, 0, 0, ..., 0]

    for root in roots:
        for i in range(N - 1, -1, -1):  # Start from the last non-zero coefficient
            print(coefs[i], root, coefs[i] * root)
            coefs[i + 1] += coefs[i] * root
            print([c.__abs__() for c in coefs])
    
    return coefs


field = galois.GF(2**8)
q = from_roots2([1, 2, 3, 4], field)
print(q)

poly = galois.Poly(q, field)
print(poly)
print(poly(1))
print(poly(2))
print(poly(3))
print(poly(4))
print(poly(5))
