//! # Rijndaels Galois Field `F_2^8` for [`u8`].

use crate::{arith::FieldArith, subroutines::prg::PRG};
use std::num::Wrapping;

/// The primitive polynomial x^4 + x^3 + x + 1 (0b0001_1011)
#[allow(dead_code)]
pub(super) const MODULUS: u8 = 0x1B;
/// The generator polynomial x + 1 ({03}) of the multiplicative group of GF(2^8)
const _GENERATOR: u8 = 0x03;
/// The order of the multiplicative group of GF(2^8)
const ORDER: u16 = 0xff;

impl FieldArith for u8 {
    /// Field addition operation
    ///
    /// Addition in GF(2^8) is the same as XOR operation
    fn field_add(&self, rhs: u8) -> Self {
        gf256_add(*self, rhs)
    }

    /// Field subtraction operation
    ///
    /// Subtraction in GF(2^8) is the same as addition
    fn field_sub(&self, rhs: u8) -> Self {
        gf256_add(*self, rhs)
    }

    fn field_mul(&self, rhs: u8) -> Self {
        gf256_mul(*self, rhs)
    }

    fn field_mul_inverse(&self) -> Self {
        gf256_mul_inverse_lookup(*self)
    }

    fn field_mul_identity() -> Self {
        1u8
    }

    fn field_add_identity() -> Self {
        0u8
    }

    fn field_pow(&self, exp: u8) -> Self {
        gf256_pow_lookup(*self, exp)
    }

    fn field_neg(&self) -> Self {
        *self
    }

    fn field_sample(prg: &mut PRG) -> Self {
        let mut res = [0; 1];
        prg.sample_field_fq_elements(&mut res);
        res[0]
    }
}

// Precomputed tables for fast multiplication and division in GF(2^8) using the generator polynomial x + 1 ({03})

/// Table lookup for g^i where g = 0x03. Double the size to avoid modulo operation.
///
/// Found using python galois package (https://pypi.org/project/galois/)
/// GF256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
/// GF256._EXP
const POWER_TABLE_0X03: [u8; 512] = [
    1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115,
    149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217,
    112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
    76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208,
    107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240,
    11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174,
    233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195,
    94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
    239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175,
    234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176,
    203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54,
    90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151,
    162, 253, 28, 36, 108, 180, 199, 82, 246, 1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161,
    248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92,
    228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204,
    79, 209, 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8,
    24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118,
    154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125,
    135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194,
    93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156,
    191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
    155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99,
    165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168,
    227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167,
    242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1, 0,
];

/// Extension function for the lookup table
fn power_lookup(a: u16) -> u8 {
    POWER_TABLE_0X03[a as usize]
}

/// Table lookup for log_g(a) where g = 0x03. Note that log_g(0) is undefined.
/// Found using python galois package (https://pypi.org/project/galois/)
/// GF256 = galois.GF(2**8)
/// GF256._LOG
const LOG_TABLE_0X03: [u16; 256] = [
    0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129,
    239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166,
    114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
    150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48,
    191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58,
    107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243,
    115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44,
    215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23,
    196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82,
    161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63,
    91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146,
    217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254,
    24, 13, 99, 140, 128, 192, 247, 112, 7,
];

/// Accessing log tables
fn log_lookup(a: u8) -> u16 {
    LOG_TABLE_0X03[a as usize]
}

/// Function for GF(256) addition
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Function for GF(256) multiplication between two u8
fn gf256_mul(a: u8, b: u8) -> u8 {
    if (a == 0) || (b == 0) {
        return 0;
    }
    _mul_lookup(a, b)
}

/// Multiplication from the spec implementation
/// TODO: Small benchmark with different multiplication functions
pub(super) fn _mul_spec(a: u8, b: u8) -> u8 {
    let a = Wrapping(a);
    let b = Wrapping(b);
    let one = Wrapping(1_u8);
    let modulus = Wrapping(MODULUS);
    let mut r: Wrapping<u8> = -(b >> 7) & a;
    r = (-(b >> 6 & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    r = (-(b >> 5 & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    r = (-(b >> 4 & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    r = (-(b >> 3 & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    r = (-(b >> 2 & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    r = (-(b >> 1 & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    r = (-(b & one) & a) ^ (-(r >> 7) & modulus) ^ (r + r);
    return r.0;
}

fn _mul_wiki(a: u8, b: u8) -> u8 {
    // TODO: Lookup carryless multiplication in Rust clmul
    let mut r: u8 = 0;
    let mut a = a.clone();
    let mut b = b.clone();
    while a != 0 && b != 0 {
        if (b & 1) != 0 {
            // f the polynomial for b has a constant term, add the corresponding a to p
            r ^= a // addition in GF(2^m) is an XOR of the polynomial coefficients
        }

        if (a & 0x80) != 0 {
            // If the polynomial for a has a highest term, reduce it modulo the irreducible polynomial
            a = (a << 1) ^ MODULUS; // subtract (XOR) the primitive polynomial –
                                    // you can change it but it must be irreducible and %2 == 1
        } else {
            a <<= 1
        }
        b >>= 1
    }

    r
}

/// Multiplication using log table lookup a * b = g^(log_g(a) + log_g(b))
fn _mul_lookup(a: u8, b: u8) -> u8 {
    let log_a = log_lookup(a);
    let log_b = log_lookup(b);
    let res = log_a + log_b;
    power_lookup(res)
}

/// using lookup table for power: a^b = g^(log_g(a^b)) = g^(b * log_g(a)) = g^(b * log_g(a) mod |g|)
fn gf256_pow_lookup(a: u8, b: u8) -> u8 {
    if b == 0 {
        return 1;
    }

    if a == 0 {
        return 0;
    }

    let log_a = log_lookup(a);
    let res = ((b as u16) * log_a) % ORDER;
    power_lookup(res)
}

/// Inverse using log table lookup a^-1 = g^(|g| - log_g(a))
fn gf256_mul_inverse_lookup(a: u8) -> u8 {
    let log_a = log_lookup(a);
    let log_a_inv = ORDER - log_a;
    power_lookup(log_a_inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arith::test_field_definitions, constants::params::PARAM_SEED_SIZE, subroutines::prg::PRG
    };

    /// TODO: remove these tests when we have used the proper test vectors
    // #[test]
    // fn test_all_add_cases() {
    //     // Test all possible addition cases
    //     // gf256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
    //     for a in 0..=255 {
    //         for b in 0..=255 {
    //             assert_eq!(
    //                 gf256_add(a, b),
    //                 ADD_TESTS[b as usize][a as usize],
    //                 "Failed for a: {}, b: {}",
    //                 a,
    //                 b
    //             );
    //         }
    //     }
    // }

    // #[test]
    // fn test_all_mul_cases() {
    //     // Generated from galios package
    //     // gf256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
    //     for a in 0..=255 {
    //         for b in 0..=255 {
    //             assert_eq!(
    //                 gf256_mul(a, b),
    //                 MUL_TESTS[b as usize][a as usize],
    //                 "Failed for a: {}, b: {}",
    //                 a,
    //                 b
    //             );
    //         }
    //     }
    // }

    #[test]
    fn test_gf256_definitions() {
        let mut prg = PRG::init(&[2u8; PARAM_SEED_SIZE], None);
        let [a, b, c] = *prg.sample_field_fq_elements_vec(3) else {
            panic!("Failed to sample 3 field elements");
        };

        test_field_definitions(a, b, c);
    }

    #[test]
    fn test_gf256_pow() {
        let mut prg = PRG::init(&[2u8; PARAM_SEED_SIZE], None);
        let [a, b, c] = *prg.sample_field_fq_elements_vec(3) else {
            panic!("Failed to sample 3 field elements");
        };

        assert!(a != 0 && b != 0);

        let pow = a.field_pow(b);

        let mut manual = 1;
        for _ in 0..b {
            manual = manual.field_mul(a);
        }

        // a^b = a * a * a * ... * a (b times)
        assert_eq!(pow, manual);
        assert_eq!(a.field_pow(0), 1);
        assert_eq!(0.field_pow(0), 1);
        assert_eq!(0.field_pow(2), 0);

        // a^b * a^c = a^(b+c) - Note that "+" is not in the
        let ab = a.field_pow(b);
        let ac = a.field_pow(c);
        let bc: u8 = (((b as u16) + (c as u16)) % ORDER).try_into().unwrap();

        assert_eq!(ab.field_mul(ac), a.field_pow(bc));
    }

    #[test]
    #[should_panic]
    fn test_div_by_zero() {
        // Multiplicative identity with additive identity is None:
        2u8.field_div(u8::field_add_identity());
    }

    #[test]
    fn test_evaluate_polynomial() {
        // Test made using python galois package (https://pypi.org/project/galois/)
        // python:
        // >>> import galois
        // >>> GF256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
        // >>> GF256.properties
        // 'Galois Field:\n  name: GF(2^8)\n  characteristic: 2\n  degree: 8\n  order: 256\n  irreducible_poly: x^8 + x^4 + x^3 + x^2 + 1\n  is_primitive_poly: True\n  primitive_element: x'
        // >>> p = galois.Poly([1,2,3,4,5], field=GF256)
        // >>> p(6)
        // GF(220, order=2^8)
        let coeffs = vec![5, 4, 3, 2, 1];
        let x = 6u8;
        let expected = 218_u8;

        assert_eq!(x.field_eval_polynomial(&coeffs), expected);
    }
}
