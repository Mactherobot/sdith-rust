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
fn _mul_spec(a: u8, b: u8) -> u8 {
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
    fn test_all_add_cases() {
        // Test all possible addition cases
        // gf256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
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
        // Generated from galios package
        // gf256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
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
            .sample_field_elements_gf256_vec(3)
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
