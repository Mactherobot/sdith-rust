//! Operations on polynomials over GF(2^8).
//!
//! Implementations use Horner's method for polynomial evaluation for efficiency.

use crate::arith::FieldArith as _;


/// Evaluate a polynomial at a point using Horner's method.
/// coeffs: Coefficients of the polynomial in increasing order of degree. e.g. [1, 2, 3] represents p(x) = 3x^2 + 2x + 1
pub fn gf256_evaluate_polynomial_horner(coeffs: &[u8], x: u8) -> u8 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let degree = coeffs.len() - 1;
    let mut acc = coeffs[degree].clone();
    for i in (0..degree).rev() {
        acc = acc.field_mul(x);
        acc = acc.field_add(coeffs[i]);
    }
    acc
}

/// Evaluate a polynomial at a point using Horner's method. Adds leading coefficient 1 to the polynomial for monic.
pub fn gf256_evaluate_polynomial_horner_monic(coeffs: &[u8], x: u8) -> u8 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let degree = coeffs.len() - 1;
    let mut acc = 1;
    for i in (0..=degree).rev() {
        acc = acc.field_mul(x);
        acc = acc.field_add(coeffs[i]);
    }
    acc
}

/// The function divides the input polynomial P_in(X) by the binomial (X−α), assuming P_in(X) is a monic polynomial (a polynomial whose leading coefficient is 1). It outputs the resulting quotient polynomial Q(X).
/// If (X-alpha) divides P_in, returns P_in / (X-alpha)
pub fn gf256_remove_one_degree_factor_monic(
    q_out: &mut [u8],
    p_in: &[u8],
    in_degree: usize,
    alpha: u8,
) {
    q_out[in_degree - 1] = 1_u8; // Monic polynomial: a polynomial whose leading coefficient is 1; e.g. X^3 + 23X^2 + 34X + 45

    // Start from the second last element
    for i in (0..=in_degree - 2).rev() {
        q_out[i] = p_in[i + 1].field_add(alpha.field_mul(q_out[i + 1])); // Q_i = P_i+1 + alpha * Q_i+1
    }
}

#[cfg(test)]
mod test_poly_ops {
    use super::*;

    #[test]
    fn test_evaluate_polynomial_horner() {
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

        assert_eq!(gf256_evaluate_polynomial_horner(&coeffs, x), expected);
        assert_eq!(
            gf256_evaluate_polynomial_horner_monic(&vec![5, 4, 3, 2], x),
            expected
        );
    }

    #[test]
    fn test_remove_one_degree_factor_monic() {
        let p_in: [u8; 4] = [112_u8, 45_u8, 195_u8, 1_u8];
        let alpha = 3_u8;
        let mut p_out = [0_u8; 3];
        let expected = [118, 192, 1];

        gf256_remove_one_degree_factor_monic(&mut p_out, &p_in, 3, alpha);
        assert_eq!(p_out, expected);
    }
}
