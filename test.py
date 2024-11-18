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


field = gf256

import numpy as np

# fmt: off
mat = [40, 203, 210, 253, 50, 23, ] # 192, 187, 103, 8, 200, 163, 86, 118, 177, 244, 181, 224, 27, 79, 167, 251, 133, 10, 217, 92, 190, 105, 242, 174, 3, 63, 37, 32, 246, 182, 80, 82, 14, 99, 144, 24, 2, 165, 238, 215, 150, 62, 194, 115, 75, 34, 201, 159, 202, 219, 49, 216, 241, 101, 209, 77, 29, 85, 96, 91, 58, 56, 11, 71, 69, 16, 47, 93, 36, 126, 38, 248, 118, 70, 1, 13, 4, 57, 45, 107, 98, 5, 84, 76, 68, 78, 19, 9, 21, 112]
# fmt: on

# convert to field values
mat = [field(a) for a in mat]
mat = np.array(mat)

mat = mat.reshape(2, 3)

vec = np.array([field(2), field(3), field(4)])

for v in mat @ vec:
    print(v, ",", end="")
