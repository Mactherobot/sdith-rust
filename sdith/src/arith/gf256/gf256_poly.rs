// ----------------------- Polynomial operations -----------------------

use crate::arith::gf256::gf256_arith::{gf256_add, gf256_mul};

pub(crate) fn gf256_evaluate_polynomial_horner(coeffs: &Vec<u8>, x: u8) -> u8 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let degree = coeffs.len() - 1;
    let mut acc = coeffs[degree].clone();
    for i in (0..degree).rev() {
        acc = gf256_mul(acc, x);
        acc = gf256_add(acc, coeffs[i]);
    }
    return acc;
}

pub(crate) fn gf256_evaluate_polynomial_horner_monic(coeffs: &Vec<u8>, x: u8) -> u8 {
    assert!(coeffs.len() > 0 && coeffs.len() < u32::MAX as usize);
    let degree = coeffs.len() - 1;
    let mut acc = 1;
    for i in (0..degree).rev() {
        acc = gf256_mul(acc, x);
        acc = gf256_add(acc, coeffs[i]);
    }
    return acc;
}

/// The function divides the input polynomial P_in(X) by the binomial (X−α), assuming P_in(X) is a monic polynomial (a polynomial whose leading coefficient is 1). It outputs the resulting quotient polynomial Q(X).
/// If (X-alpha) divides P_in, returns P_in / (X-alpha)
pub(crate) fn gf256_remove_one_degree_factor_monic(q_out: &mut [u8], p_in: &[u8], alpha: u8) {
    let in_degree = p_in.len() - 1;
    assert!(q_out.len() >= in_degree, "Output array must be larger than input coefficient array `p_in`. p_in: {}, q_out: {}", in_degree, q_out.len());

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
        let coeffs = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let x = 0x06;
        let expected = 237_u8;

        assert_eq!(gf256_evaluate_polynomial_horner(&coeffs, x), expected);
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
