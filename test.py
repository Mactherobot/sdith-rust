import galois
import pyperclip

gf256 = galois.GF(
    2**8, irreducible_poly=galois.Poly([1, 0, 0, 0, 1, 1, 0, 1, 1], field=galois.GF2)
)
print(gf256.properties)

# mul_tests = [
#     [(gf256(a) * gf256(b)).__abs__() for a in range(256)]  for b in range(256)
# ]

# add_tests = [
#     [(gf256(a) + gf256(b)).__abs__() for a in range(256)]  for b in range(256)
# ]
# pyperclip.copy(add_tests)


def from_roots_rev(roots, field):
    roots = [field(r) for r in roots]
    N = len(roots)
    coefs = [field(0)] * (N + 1)
    coefs[0] = roots[0]
    coefs[1] = field(1)

    for k in range(2, N + 1):
        coefs[k] = field(1)
        for i in range(k - 2, -1, -1):
            coefs[i + 1] = coefs[i] + roots[k - 1] * coefs[i + 1]
        coefs[0] *= roots[k - 1]

    return coefs


def from_roots2(roots, field):
    roots = [field(r) for r in roots]
    N = len(roots)
    coefs = [field(1)] + [field(0)] * N  # Initialize [1, 0, 0, ..., 0]

    for root in roots:
        for i in range(N - 1, -1, -1):  # Start from the last non-zero coefficient
            coefs[i + 1] += coefs[i] * root

    return coefs


# field = gf256
# q = from_roots_rev([1, 2, 3, 4], field)
# q.reverse()
# print(q)

# poly = galois.Poly(q, field)
# print(poly)
# print(poly(1))
# print(poly(2))
# print(poly(3))
# print(poly(4))
# print(poly(5))

a = gf256(57)
b = 139
c = 203

print("a^b: ", a**b)
print("a^c: ", a**c)

print("a^b: ", a**b)
print("a^b * a^c: ", a**b * a**c)
print("a^(b+c): ", a ** (b + c))
print("b+c: ", b + c)

print(gf256._positive_power)
