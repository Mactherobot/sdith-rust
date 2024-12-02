// Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`. Here "/" means "over"

use crate::subroutines::prg::prg::PRG;

use super::{
    gf256_arith::{gf256_add, gf256_mul},
    FieldArith,
};

const _GF256_16_ONE: [u8; 2] = [1, 0];
const GF256_32_ONE: [u8; 4] = [1, 0, 0, 0];

/// First field extension F_256^2 = F_256[X] / (X^2 + X + 32)
///
/// An element of the field is represented as a pair of bytes (a,b) corresponding to a + bX
/// where a and b are elements of F_256

/// Addition: Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`
///
/// (a + bX) + (c + dX) = (a + c) + (b + d)X
#[inline(always)]
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
#[inline(always)]
fn gf256_ext16_mul(_a: [u8; 2], _b: [u8; 2]) -> [u8; 2] {
    let [a, b] = _a;
    let [c, d] = _b;
    let bd = b.field_mul(d);
    let ac = a.field_mul(c);
    let sum_ab = a.field_add(b);
    let sum_cd = c.field_add(d);

    let c0 = u8::field_add(&ac, gf256_mul(bd, 0x20));
    let c1 = u8::field_sub(&sum_ab.field_mul(sum_cd), ac);
    [c0, c1]
}

/// Field extension `F_q^2 = F_q[X] / (X^2 + X + 32)`: Multiplication by 32
///
///   32 in F_256^2 = 0 + 32X
///
///   (0, 32X) * (a + bX) = (0a + 32b * 32) + (0b + 32a + 32b)X
///                       = (32^2)b + 32(a + b)X
#[inline(always)]
fn gf256_ext16_mul32(_a: [u8; 2]) -> [u8; 2] {
    let [a, b] = _a;
    let c0 = b.field_mul(0x20).field_mul(0x20);
    let c1 = a.field_add(b).field_mul(0x20);
    [c0, c1]
}

#[cfg(test)]
mod ext16_tests {
    use super::*;

    use crate::{constants::params::PARAM_SEED_SIZE, subroutines::prg::prg::PRG};

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

pub type FPoint = [u8; 4];

impl FieldArith for FPoint {
    fn field_one() -> Self {
        GF256_32_ONE
    }

    fn field_zero() -> Self {
        [0u8; 4]
    }

    fn field_neg(&self) -> Self {
        *self
    }

    fn field_sample(prg: &mut PRG) -> Self {
        gf256_ext32_sample(prg)
    }

    fn field_add(&self, rhs: Self) -> Self {
        gf256_ext32_add(*self, rhs)
    }

    fn field_sub(&self, rhs: Self) -> Self {
        gf256_ext32_add(*self, rhs)
    }

    fn field_mul(&self, rhs: Self) -> Self {
        gf256_ext32_mul(*self, rhs)
    }

    fn field_mul_inverse(&self) -> Self {
        panic!("Multiplicative inverse not implemented for F_q^4");
    }
}

/// Addition: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
///
/// For u = (p,q) = p + qZ
///
/// u + v = (p + qZ) + (r + sZ) = (p + r) + (q + s)Z
#[inline(always)]
pub(super) fn gf256_ext32_add(a: FPoint, b: FPoint) -> FPoint {
    let [p0, p1, q0, q1] = a;
    let [r0, r1, s0, s1] = b;

    let [r0, r1] = gf256_ext16_add([p0, p1], [r0, r1]);
    let [r2, r3] = gf256_ext16_add([q0, q1], [s0, s1]);

    [r0, r1, r2, r3]
}

/// Multiplication: Field extension `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
///
/// For u = (p,q) = p + qZ,
///
/// u * v = (p + qZ) * (r + sZ)
///       = pr + psZ + qrZ + qsZ^2
///       = pr + (ps + qr)Z + qs(Z + 32X)  # Z^2 = Z + 32X i.e. modulo
///       = pr + (ps + qr)Z + qsZ + 32qsX
///       = (pr + 32qsX) + (ps + qr + qs)Z
///       = (pr + 32qsX) + ((p + q) * (r + s) - pr)Z
#[inline(always)]
pub(super) fn gf256_ext32_mul(a: FPoint, b: FPoint) -> FPoint {
    let [p0, p1, q0, q1] = a;
    let [r0, r1, s0, s1] = b;

    let qs = gf256_ext16_mul([q0, q1], [s0, s1]);
    let pr = gf256_ext16_mul([p0, p1], [r0, r1]);
    let p_plus_q = gf256_ext16_add([p0, p1], [q0, q1]);
    let r_plus_s = gf256_ext16_add([r0, r1], [s0, s1]);

    let [r0, r1] = gf256_ext16_add(gf256_ext16_mul32(qs), pr);
    let [r2, r3] = gf256_ext16_add(gf256_ext16_mul(p_plus_q, r_plus_s), pr);

    [r0, r1, r2, r3]
}

/// Multiplication in the 32-bit extended field
#[inline(always)]
fn gf256_ext32_gf256_mul(a: u8, b: FPoint) -> FPoint {
    let [b0, b1, b2, b3] = b;
    let c0 = a.field_mul(b0);
    let c1 = a.field_mul(b1);
    let c2 = a.field_mul(b2);
    let c3 = a.field_mul(b3);
    [c0, c1, c2, c3]
}

/// Sample a value from the extended field `F_q^4 = F_q[Z] / (Z^2 + Z + 32(X))` where (X) = 256
#[inline(always)]
pub(super) fn gf256_ext32_sample(prg: &mut PRG) -> FPoint {
    prg.sample_field_fq_elements_vec(4).try_into().unwrap()
}

#[cfg(test)]
mod ext32_tests {
    use super::*;

    use crate::{
        arith::gf256::test_field_definitions, constants::params::PARAM_SEED_SIZE,
        subroutines::prg::prg::PRG,
    };

    #[test]
    fn test_field_point_definitions() {
        let mut prg = PRG::init(&[2u8; PARAM_SEED_SIZE], None);
        let [a, b, c] = *prg.sample_field_fpoint_elements_vec(3) else {
            panic!("Failed to sample 3 field elements");
        };

        test_field_definitions(a, b, c);
    }

    #[test]
    #[should_panic]
    fn test_div_by_zero() {
        // Multiplicative identity with additive identity is None:
        FPoint::field_one().field_div(FPoint::field_zero());
    }

    //// Polynomial evaluation

    #[test]
    fn test_field_eval_polynomial() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);
        let a: FPoint = gf256_ext32_sample(&mut prg);
        let poly = [a, a, a];

        let eval = a.field_eval_polynomial(&poly);
        // f(x) = ax^2 + ax^1 + x
        // f(a) = a^3 + a^2 + a
        let expected = a.field_pow(3).field_add(a.field_mul(a)).field_add(a);

        assert_eq!(eval, expected);
    }
}
