use std::ops::Mul;

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    U256,
};

#[macro_export]

/// Converts a U256 to u64. Useful for more readable assertions in tests.
macro_rules! u256_to_u64 {
    ($value:expr) => {{
        let result = u64::from_str_radix($value.to_string().as_str(), 16)
            .expect("Failed to convert U256 to u64");
        result
    }};
}

/// Computes `lhs * rhs mod modulus`
pub fn mul_mod(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    let dyn_residue_lhs = DynResidue::new(lhs, DynResidueParams::new(modulus));
    let dyn_residue_rhs = DynResidue::new(rhs, DynResidueParams::new(modulus));
    dyn_residue_lhs.mul(&dyn_residue_rhs).retrieve()
}

/// Computes `base ^ exponent mod modulus`
pub fn pow_mod(base: &U256, exponent: &U256, modulus: &U256) -> U256 {
    let dyn_residue = DynResidue::new(base, DynResidueParams::new(modulus));
    dyn_residue.pow(exponent).retrieve()
}

/// Computes `lhs / rhs mod modulus` by finding the modular inverse of `rhs` and multiplying it with `lhs`
pub fn div_mod(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    let dyn_residue_lhs = DynResidue::new(lhs, DynResidueParams::new(modulus));
    let dyn_residue_rhs = DynResidue::new(rhs, DynResidueParams::new(modulus));
    let (rhs_inverse, success) = dyn_residue_rhs.invert();
    if success.into() {
        return dyn_residue_lhs.mul(&rhs_inverse).retrieve();
    }
    panic!("No inverse exists for the given rhs");
}

pub fn evaluate_polynomial(coeffs: &Vec<U256>, x: &U256, modulus: &U256) -> U256 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let mut coeffs = coeffs.iter().enumerate();
    let mut result: U256 = coeffs.next().unwrap().1.clone();

    for (exp, coeff) in coeffs {
        let exp = U256::from(exp as u32);
        result = result.add_mod(
            &mul_mod(coeff, &pow_mod(x, &U256::from(exp), modulus), modulus),
            modulus,
        )
    }
    return result;
}

#[cfg(test)]
mod test {
    use std::ops::Rem;

    use super::*;

    #[test]
    fn test_mul_mod() {
        let a = 7_u32;
        let b = 3_u32;
        let c = 5_u32;

        assert_eq!(
            mul_mod(&U256::from(a), &U256::from(b), &U256::from(c)),
            U256::from((a * b).rem(c))
        );
        assert_eq!(
            mul_mod(&U256::from(c), &U256::from(a), &U256::from(b)),
            U256::from((c * a).rem(b))
        );
        assert_eq!(
            mul_mod(&U256::from(b), &U256::from(c), &U256::from(a)),
            U256::from((b * c).rem(a))
        );
    }

    #[test]
    fn test_pow_mod() {
        let a = 2_u32;
        let b = 4_u32;
        let c = 23_u32;

        assert_eq!(
            pow_mod(&U256::from(a), &U256::from(b), &U256::from(c)),
            U256::from_u32(16)
        );
    }

    #[test]
    fn test_div_mod() {
        let a = 10_u32;
        let b = 2_u32;
        let c = 5_u32;
        let modulus = 15_u32;

        assert_eq!(
            div_mod(&U256::from(a), &U256::from(b), &U256::from(modulus)),
            U256::from(c)
        );
    }

    #[test]
    fn test_evaluate_polynomial() {
        // f(x) = 1 + 2x + 3x^2
        let coeffs = vec![U256::from(1_u32), U256::from(2_u32), U256::from(3_u32)];
        // f(2) mod 5 = 1 + 2*2 + 3*2^2 mod 5 = 2
        let x = U256::from(2_u32);
        let modulus = U256::from(5_u32);

        assert_eq!(
            evaluate_polynomial(&coeffs, &x, &modulus),
            U256::from(2_u32)
        );
    }
}
