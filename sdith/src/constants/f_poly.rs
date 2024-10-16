use crate::arith::gf256::FieldArith;

/// Compute the vanishing polynomial F from the set {f1, f2, ..., f_N}.
/// Returns the coefficients of F ([3,2,1] = x^3 + 2x^2 + 3x).
/// F(X) = prod_{i=1}^{N} (X - f_i) and F(f_i) = 0.
///
/// Essentially this computes the monic polynomial from the roots (f1). I.e. Q(root) = 0. Returns truncated polynomial to N. (removing the leading coefficient 1)
pub(crate) fn compute_vanishing_polynomial<const N: usize>(set: &[u8; N]) -> [u8; N] {
    let mut coeffs = [1u8; N];

    for (i, fi) in set.iter().enumerate() {
        for j in (1..=i).rev() {
            coeffs[j] = coeffs[j - 1].field_add(coeffs[j].field_mul(*fi));
        }
        coeffs[0] = coeffs[0].field_mul(*fi);
    }
    coeffs
}

#[cfg(test)]
mod test_f_poly {
    use crate::{
        arith::gf256::gf256_poly::{
            gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
        },
        constants::{params::PARAM_CHUNK_M, precomputed::PRECOMPUTED_F_POLY},
    };

    use super::*;

    #[test]
    fn test_compute_vanishing_polynomial_f() {
        // F = the vanishing polynomial for the set {f_1, f_2, ..., f_m} = [1..PARAM_M]
        // F(X) = prod_{i=1}^{PARAM_M} (X - f_i)
        let f_poly = compute_vanishing_polynomial::<PARAM_CHUNK_M>(
            (1..=PARAM_CHUNK_M as u8)
                .collect::<Vec<u8>>()
                .as_slice()
                .try_into()
                .unwrap(),
        );

        for i in 1..PARAM_CHUNK_M {
            assert_eq!(gf256_evaluate_polynomial_horner_monic(&f_poly, i as u8), 0);
            assert_eq!(
                gf256_evaluate_polynomial_horner_monic(&f_poly, i as u8),
                gf256_evaluate_polynomial_horner(&PRECOMPUTED_F_POLY, i as u8)
            );
        }
    }
}
