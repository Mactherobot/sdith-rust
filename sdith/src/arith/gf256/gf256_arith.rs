// Galois field 256 F_256 operations

use std::{
    fmt::Debug,
    num::Wrapping,
    ops::{Add, Div, Mul, Sub},
};

use num_traits::CheckedDiv;

const MODULUS: u8 = 0x1B; // The primitive polynomial x^4 + x^3 + x + 1 (0b0001_1011)
const _GENERATOR: u8 = 0x03; // The generator polynomial x + 1 ({03}) of the multiplicative group of GF(2^8)
const ORDER: u16 = 0xff; // The order of the multiplicative group of GF(2^8)

// Precomputed tables for fast multiplication and division in GF(2^8) using the generator polynomial x + 1 ({03})

/// Table lookup for g^i where g = 0x03. Double the size to avoid modulo operation.
///
/// Found using python galois package (https://pypi.org/project/galois/)
/// GF256 = galois.GF(2**8)
/// GF256._EXP
const POWER_TABLE_0X03: [u8; 512] = [
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117,
    234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181,
    119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
    95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187,
    107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136,
    13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197,
    151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
    77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198,
    145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149,
    55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167,
    83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72,
    144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207,
    131, 27, 54, 108, 216, 173, 71, 142, 1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135,
    19, 38, 76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156,
    37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93,
    186, 105, 210, 185, 111, 222, 161, 95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30,
    60, 120, 240, 253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226,
    217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248,
    237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79,
    158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213,
    183, 115, 230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227,
    219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200,
    141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195,
    155, 43, 86, 172, 69, 138, 9, 18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139,
    11, 22, 44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1, 0,
];

fn power_lookup(a: u16) -> u8 {
    POWER_TABLE_0X03[a as usize]
}

/// Table lookup for log_g(a) where g = 0x03. Note that log_g(0) is undefined.
/// Found using python galois package (https://pypi.org/project/galois/)
/// GF256 = galois.GF(2**8)
/// GF256._LOG
const LOG_TABLE_0X03: [u16; 256] = [
    0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239,
    129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218,
    240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6,
    191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143,
    150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58,
    40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243,
    167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165,
    153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207,
    205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57,
    83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
    108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156,
    169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116,
    214, 244, 234, 168, 80, 88, 175,
];

fn log_lookup(a: u8) -> u16 {
    LOG_TABLE_0X03[a as usize]
}

pub(crate) fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// JUST ADD... DUH its XOR
pub(crate) fn gf256_sub(a: u8, b: u8) -> u8 {
    gf256_add(a, b)
}

pub(crate) fn gf256_mul(a: u8, b: u8) -> u8 {
    if (a == 0) || (b == 0) {
        return 0;
    }
    _mul_lookup(a, b)
}

pub(crate) fn gf256_pow(a: u8, b: u8) -> u8 {
    let mut acc = 1;
    for _ in 0..b {
        acc = gf256_mul(acc, a);
    }
    acc
}

/// Multiplication from the spec implementation
fn mul_spec(a: u8, b: u8) -> u8 {
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

/// Inverse using log table lookup a^-1 = g^(|g| - log_g(a))
pub(crate) fn gf256_mul_inverse_lookup(a: u8) -> u8 {
    let log_a = log_lookup(a);
    let log_a_inv = ORDER - log_a;
    power_lookup(log_a_inv)
}

pub(crate) fn div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_mul_inverse_lookup(b))
}

#[derive(Clone, Copy)]
struct GF256(u8);

impl Add for GF256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        GF256(gf256_add(self.0, rhs.0))
    }
}

impl Sub for GF256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        GF256(gf256_add(self.0, rhs.0))
    }
}

impl Mul for GF256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        GF256(gf256_mul(self.0, rhs.0))
    }
}

impl Div for GF256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        GF256(div(self.0, rhs.0))
    }
}

impl CheckedDiv for GF256 {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        if rhs.0 == 0 {
            return None;
        }
        Some(self.clone() / rhs.clone())
    }
}

impl PartialEq for GF256 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Debug for GF256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:02x} ({}, {:8b})", self.0, self.0, self.0)
    }
}

// Macro to create a GF256 element
macro_rules! gf256 {
    ($val:expr) => {
        GF256($val)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arith::gf256::{addition_tests::ADD_TESTS, multiplication_tests::MUL_TESTS},
        constants::params::PARAM_SEED_SIZE,
        subroutines::prg::prg::PRG,
    };

    #[test]
    fn test_arith_edgecase() {
        // edge case that fails:
        // a = 0x39 (57) b = 0x8b (139) c = 0xcb (203) => a * (b + c) = 0xe6 (230)
        let a = gf256!(0x39);
        let b = gf256!(0x8b);
        let c = gf256!(0xcb);
        let expected = gf256!(230u8);

        let bc = b + c;
        assert_eq!(bc, gf256!(64u8));
        let ac = a * c;
        assert_eq!(ac, gf256!(169u8));
        let ab = a * b;
        assert_eq!(ab, gf256!(79u8));
        assert_eq!(a * (b + c), expected);
        assert_eq!(a * b + a * c, expected);
    }

    #[test]
    fn test_all_add_cases() {
        for a in 0..=255 {
            for b in 0..=255 {
                assert_eq!(
                    gf256_add(a, b),
                    ADD_TESTS[b as usize][a as usize],
                    "Failed for a: {}, b: {}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn test_all_mul_cases() {
        for a in 0..=255 {
            for b in 0..=255 {
                assert_eq!(
                    gf256_mul(a, b),
                    MUL_TESTS[b as usize][a as usize],
                    "Failed for a: {}, b: {}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn test_gf256_definitions() {
        let mut prg = PRG::init(&[2u8; PARAM_SEED_SIZE], None);
        let [a, b, c] = *prg
            .sample_field_elements_gf256(3)
            .iter()
            .map(|x| gf256!(*x))
            .collect::<Vec<GF256>>()
            .as_slice()
        else {
            panic!("Failed to sample 3 field elements");
        };

        // Commutativity of addition and multiplication:
        assert_eq!(a + b, b + a);
        assert_eq!(a * b, b * a);

        // Associativity of addition and multiplication:
        assert_eq!(a + (b + c), (a + b) + c);
        assert_eq!(a * (b * c), (a * b) * c);

        // Identity of addition and multiplication:
        assert_eq!(a + gf256!(0), a);
        assert_eq!(a * gf256!(1), a);

        // Inverse of addition and multiplication:
        assert_eq!(a - a, gf256!(0));
        assert_eq!((a * b) / b, a);

        // Multiplicative identity with additive identity is None:
        assert_eq!(a.checked_div(&gf256!(0)), None);

        // Distributivity of multiplication over addition:
        assert_eq!(a * (b + c), a * b + a * c);
    }
}
