// Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`. Here "/" means "over"

use crate::subroutines::prg::{self, prg::PRG};

use super::gf256_arith::{gf256_add, gf256_mul, gf256_sub};

const GF256_16_ONE: [u8; 2] = [1, 0];
const GF256_32_ONE: [u8; 4] = [1, 0, 0, 0];

/// First field extension F_256^2 = F_256[X] / (X^2 + X + 32)
///
/// An element of the field is represented as a pair of bytes (a,b) corresponding to a + bX
/// where a and b are elements of F_256

/// Addition: Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`
///
/// (a + bX) + (c + dX) = (a + c) + (b + d)X
fn gf256_ext16_add(a: [u8; 2], b: [u8; 2]) -> [u8; 2] {
    [gf256_add(a[0], b[0]), gf256_add(a[1], b[1])]
}

/// Multiplication: Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`
///
/// X^2 + X + 32 = 0 => X^2 = X + 32
///
/// (a + bX) * (c + dX) = ac + (ad + bc) * X + bd * X^2
///                     = ac + (ad + bc) * X + bd * (X + 32)
///                     = (ac + bd * 32) + (ad + bc + bd)X
///                     = (ac + bd * 32) + ((a + b) * (c + d) - ac)X
///                     = c0 + c1X
fn gf256_ext16_mul(_a: [u8; 2], _b: [u8; 2]) -> [u8; 2] {
    let [a, b] = _a;
    let [c, d] = _b;
    let bd = gf256_mul(b, d);
    let ac = gf256_mul(a, c);
    let sum_ab = gf256_add(a, b);
    let sum_cd = gf256_add(c, d);

    let c0 = gf256_add(ac, gf256_mul(bd, 0x20));
    let c1 = gf256_sub(gf256_mul(sum_ab, sum_cd), ac);
    [c0, c1]
}

/// Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`: Multiplication by 32
///
///   32 in F_256^2 = 0 + 32X
///
///   (0, 32X) * (a + bX) = (0a + 32b * 32) + (0b + 32a + 32b)X
///                       = (32^2)b + 32(a + b)X
fn gf256_ext16_mul32(_a: [u8; 2]) -> [u8; 2] {
    let [a, b] = _a;
    let c0 = gf256_mul(gf256_mul(b, 0x20), 0x20);
    let c1 = gf256_mul(gf256_add(a, b), 0x20);
    [c0, c1]
}

#[cfg(test)]
mod ext16_tests {
    use super::*;

    use crate::{constants::params::PARAM_SEED_SIZE, subroutines::prg::prg::PRG};

    #[test]
    fn test_f_256_16_extension() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);
        let a: [u8; 2] = prg.sample_field_fq_elements_vec(2).try_into().unwrap();
        let b: [u8; 2] = prg.sample_field_fq_elements_vec(2).try_into().unwrap();
        let c: [u8; 2] = prg.sample_field_fq_elements_vec(2).try_into().unwrap();

        // Commutativity of addition and multiplication:
        assert_eq!(gf256_ext16_add(a, b), gf256_ext16_add(b, a));
        assert_eq!(gf256_ext16_mul(a, b), gf256_ext16_mul(b, a));

        // Associativity of addition and multiplication:
        assert_eq!(
            gf256_ext16_add(a, gf256_ext16_add(b, c)),
            gf256_ext16_add(gf256_ext16_add(a, b), c)
        );
        assert_eq!(
            gf256_ext16_mul(a, gf256_ext16_mul(b, c)),
            gf256_ext16_mul(gf256_ext16_mul(a, b), c)
        );

        // Identity of addition and multiplication:
        let additive_inverse = [0u8, 0u8];
        assert_eq!(gf256_ext16_add(a, additive_inverse), a);
        let multiplicative_inverse = GF256_16_ONE;
        assert_eq!(gf256_ext16_mul(a, multiplicative_inverse), a);

        // Inverse of addition and multiplication:
        assert_eq!(gf256_ext16_add(a, a), additive_inverse);
        // No division implemented for now
        // assert_eq!((a * b) / b, a);

        // Multiplicative identity with additive identity is None:
        // No division implemented for now
        // assert_eq!(a.checked_div(&gf256!(0)), None);

        // Distributivity of multiplication over addition:
        assert_eq!(
            gf256_ext16_mul(a, gf256_ext16_add(b, c)),
            gf256_ext16_add(gf256_ext16_mul(a, b), gf256_ext16_mul(a, c))
        );
    }

    #[test]
    fn test_f_256_16_mul_32() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);
        let a: [u8; 2] = prg.sample_field_fq_elements_vec(2).try_into().unwrap();
        let n32 = [0u8, 32u8];

        let mul32 = gf256_ext16_mul32(a);
        let expected = gf256_ext16_mul(a, n32);

        assert_eq!(mul32, expected);
    }
}

// Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256

pub(crate) type FPoint = [u8; 4];

/// Addition: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_add(a: FPoint, b: FPoint) -> FPoint {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;
    let [r0, r1] = gf256_ext16_add([a0, a1], [b0, b1]);
    let [r2, r3] = gf256_ext16_add([a2, a3], [b2, b3]);

    [r0, r1, r2, r3]
}

/// Multiplication: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_mul(a: FPoint, b: FPoint) -> FPoint {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;

    let leading = gf256_ext16_mul([a2, a3], [b2, b3]);
    let cnst = gf256_ext16_mul([a0, a1], [b0, b1]);
    let sum_a = gf256_ext16_add([a0, a1], [a2, a3]);
    let sum_b = gf256_ext16_add([b0, b1], [b2, b3]);

    let [r0, r1] = gf256_ext16_add(gf256_ext16_mul32(leading), cnst);
    let [r2, r3] = gf256_ext16_add(gf256_ext16_mul(sum_a, sum_b), cnst);

    [r0, r1, r2, r3]
}

/// Exponentiation: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_pow(a: FPoint, n: usize) -> FPoint {
    // TODO: is this efficient? Used copilot to generate this
    let mut res = GF256_32_ONE;
    let mut base = a;
    let mut n = n;
    while n > 0 {
        if n & 1 == 1 {
            res = gf256_ext32_mul(res, base);
        }
        base = gf256_ext32_mul(base, base);
        n >>= 1;
    }
    res
}

/// Sample a value from the extended field `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
pub(crate) fn gf256_ext32_sample(prg: &mut PRG) -> FPoint {
    prg.sample_field_fq_elements_vec(4).try_into().unwrap()
}

#[cfg(test)]
mod ext32_tests {
    use super::*;

    use crate::{constants::params::PARAM_SEED_SIZE, subroutines::prg::prg::PRG};

    #[test]
    fn test_f_256_32_extension() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);
        let a: [u8; 4] = gf256_ext32_sample(&mut prg);
        let b: [u8; 4] = gf256_ext32_sample(&mut prg);
        let c: [u8; 4] = gf256_ext32_sample(&mut prg);

        // Commutativity of addition and multiplication:
        assert_eq!(gf256_ext32_add(a, b), gf256_ext32_add(b, a));
        assert_eq!(gf256_ext32_mul(a, b), gf256_ext32_mul(b, a));

        // Associativity of addition and multiplication:
        assert_eq!(
            gf256_ext32_add(a, gf256_ext32_add(b, c)),
            gf256_ext32_add(gf256_ext32_add(a, b), c)
        );
        assert_eq!(
            gf256_ext32_mul(a, gf256_ext32_mul(b, c)),
            gf256_ext32_mul(gf256_ext32_mul(a, b), c)
        );

        // Identity of addition and multiplication:
        let additive_inverse = [0u8, 0u8, 0u8, 0u8];
        assert_eq!(gf256_ext32_add(a, additive_inverse), a);
        let multiplicative_inverse = GF256_32_ONE;
        assert_eq!(gf256_ext32_mul(a, multiplicative_inverse), a);

        // Inverse of addition and multiplication:
        assert_eq!(gf256_ext32_add(a, a), additive_inverse);
        // No division implemented for now
        // assert_eq!((a * b) / b, a);

        // Multiplicative identity with additive identity is None:
        // No division implemented for now
        // assert_eq!(a.checked_div(&gf256!(0)), None);

        // Distributivity of multiplication over addition:
        assert_eq!(
            gf256_ext32_mul(a, gf256_ext32_add(b, c)),
            gf256_ext32_add(gf256_ext32_mul(a, b), gf256_ext32_mul(a, c))
        );
    }

    #[test]
    fn test_f_256_32_pow() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);
        let a: [u8; 4] = gf256_ext32_sample(&mut prg);
        let n = 10;

        let pow = gf256_ext32_pow(a, n);
        let mut expected = GF256_32_ONE;
        for _ in 0..n {
            expected = gf256_ext32_mul(expected, a);
        }

        assert_eq!(pow, expected);
    }

    #[test]
    fn test_f_256_32_pow_0() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);
        let a: [u8; 4] = gf256_ext32_sample(&mut prg);
        let n = 0;
        let pow = gf256_ext32_pow(a, n);
        assert_eq!(pow, GF256_32_ONE);
    }
}
