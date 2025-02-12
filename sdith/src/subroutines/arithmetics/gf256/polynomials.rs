//! Operations on polynomials over GF(2^8).
//!
//! Implementations use Horner's method for polynomial evaluation for efficiency.

use crate::subroutines::arithmetics::{
    gf256::{extensions::FPoint, vectors::gf256_mul_vector_by_scalar},
    FieldArith as _,
};

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

/// Divide monic polynomial by linear factor (X-alpha). Returns the quotient polynomial.
/// Since the input polynomial is monic,
///  - the leading coefficient of the output is 1
///  - it has (X-alpha) as a factor and leaves no remainder.
pub fn gf256_monic_polynomial_division(
    quotient_polynomial_out: &mut [u8],
    monic_polynomial_in: &[u8],
    in_length: usize,
    alpha: u8,
) {
    quotient_polynomial_out[in_length - 1] = 1_u8; // Monic polynomial: a polynomial whose leading coefficient is 1; e.g. X^3 + 23X^2 + 34X + 45

    // Start from the second last element
    for i in (0..=in_length - 2).rev() {
        quotient_polynomial_out[i] =
            monic_polynomial_in[i + 1].field_add(alpha.field_mul(quotient_polynomial_out[i + 1]));
        // Q_i = P_i+1 + alpha * Q_i+1
    }
}

/// Evaluate the polynomial at a given point in FPoint. See p. 20 of the specification.
/// Q(r) = Σ_{i=1}^{|Q|} q_i · r^i
///
/// # Arguments
/// * `poly_d` - The polynomial to evaluate coefficients in order [1, 2, 3] represents p(x) = 3x^2 + 2x + 1
/// * `powers_of_r` - The powers of the point `r`` in the field
pub fn gf256_polynomial_evaluation_in_point_r(poly_d: &[u8], powers_of_r: &[FPoint]) -> FPoint {
    assert!(powers_of_r.len() >= poly_d.len());
    let mut sum = FPoint::default();
    let degree = poly_d.len();
    // TODO: can we parallelize this?
    for i in 0..degree {
        // sum += r_j^(i-1) * q_poly_d[i]
        let mut r_i = powers_of_r[i];
        gf256_mul_vector_by_scalar(&mut r_i, poly_d[i]);
        sum = sum.field_add(r_i);
    }
    sum
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

        gf256_monic_polynomial_division(&mut p_out, &p_in, 3, alpha);
        assert_eq!(p_out, expected);
    }
}
