// ----------------------- Polynomial operations -----------------------

use crate::arith::gf256::gf256_arith::{gf256_add, gf256_mul};

/// Evaluate a polynomial at a point using Horner's method.
/// coeffs: Coefficients of the polynomial in decreasing order of degree. e.g. [1, 2, 3] represents p(x) = x^2 + 2x + 3
pub(crate) fn gf256_evaluate_polynomial_horner(coeffs: &Vec<u8>, x: u8) -> u8 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let mut acc = coeffs[0].clone();
    for i in 1..coeffs.len() {
        acc = gf256_add(coeffs[i], gf256_mul(acc, x));
    }
    return acc;
}

/// Evaluate a polynomial at a point using Horner's method. Adds leading coefficient 1 to the polynomial for monic.
pub(crate) fn gf256_evaluate_polynomial_horner_monic(coeffs: &Vec<u8>, x: u8) -> u8 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let mut acc = 1;
    for i in 0..coeffs.len() {
        acc = gf256_add(coeffs[i], gf256_mul(acc, x));
    }
    return acc;
}

/// The function divides the input polynomial P_in(X) by the binomial (X−α), assuming P_in(X) is a monic polynomial (a polynomial whose leading coefficient is 1). It outputs the resulting quotient polynomial Q(X).
/// If (X-alpha) divides P_in, returns P_in / (X-alpha)
pub(crate) fn gf256_remove_one_degree_factor_monic(q_out: &mut [u8], p_in: &[u8], alpha: u8) {
    let in_degree = p_in.len() - 1;
    assert!(
        q_out.len() >= in_degree,
        "Output array must be larger than input coefficient array `p_in`. p_in: {}, q_out: {}",
        in_degree,
        q_out.len()
    );

    q_out[in_degree - 1] = 1_u8; // Monic polynomial: a polynomial whose leading coefficient is 1; e.g. X^3 + 23X^2 + 34X + 45

    // Start from the second last element
    for i in (0..=in_degree - 2).rev() {
        q_out[i] = gf256_add(p_in[i + 1], gf256_mul(alpha, q_out[i + 1])); // Q_i = P_i+1 + alpha * Q_i+1
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
        // >>> GF256 = galois.GF(2**8)
        // >>> GF256.properties
        // 'Galois Field:\n  name: GF(2^8)\n  characteristic: 2\n  degree: 8\n  order: 256\n  irreducible_poly: x^8 + x^4 + x^3 + x^2 + 1\n  is_primitive_poly: True\n  primitive_element: x'
        // >>> p = galois.Poly([1,2,3,4,5], field=GF256)
        // >>> p(6)
        // GF(220, order=2^8)
        let coeffs = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let x = 0x06;
        let expected = 220_u8;

        assert_eq!(gf256_evaluate_polynomial_horner(&coeffs, x), expected);
        assert_eq!(
            gf256_evaluate_polynomial_horner_monic(&vec![2, 3, 4, 5], x),
            expected
        );
    }

    #[test]
    fn test_remove_one_degree_factor_monic() {
        let p_in: [u8; 4] = [112_u8, 45_u8, 195_u8, 1_u8];
        let alpha = 3_u8;
        let mut p_out = [0_u8; 3];
        let expected = [118, 192, 1];

        gf256_remove_one_degree_factor_monic(&mut p_out, &p_in, alpha);
        assert_eq!(p_out, expected);
    }
}
