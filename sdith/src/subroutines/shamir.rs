use crate::helpers::gf256::{add, div, evaluate_polynomial_horner, mul, sub};

use super::prg::prg::PRG;

/// Share a secret `v` among `n` parties using Shamir's secret sharing scheme.
///
/// Given an integer valued data `v`, we
/// pick a prime p which is bigger than both `v` and `n`
pub(crate) fn share(v: &u8, n: usize, k: usize, prg: &mut PRG) -> Vec<(u8, u8)> {
    // Generate a random polynomial of degree `k - 1` with the constant term `v`.
    // Coefficients are chosen uniformly at random from the field `GF256`.
    let mut coefficients = vec![v.clone()];
    coefficients.append(&mut prg.sample_field_elements_gf256(k - 1));
    share_coeffs(coefficients, n)
}

fn share_coeffs(coefficients: Vec<u8>, n: usize) -> Vec<(u8, u8)> {
    // Evaluate the polynomial at `n` distinct points in the field `Z_p`.
    let mut shares: Vec<(u8, u8)> = Vec::with_capacity(n);
    assert!(n < u8::MAX as usize);
    for i in 1..=n {
        let x: u8 = i.try_into().expect("Failed to convert usize to u8");
        let y = evaluate_polynomial_horner(&coefficients, &x);
        shares.push((x, y));
    }

    return shares;
}

pub(crate) fn reconstruct(shares: &Vec<(u8, u8)>) -> u8 {
    let mut result = 0_u8;
    let k = shares.len();
    for j in 0..k {
        let (x_j, yj) = shares[j];

        // prod = Π_{m=0}^{threshold-1} m != j (x_m / (x_m - x_j))
        let mut _prod = 1_u8;
        for m in 0..k {
            if m != j {
                let x_m = shares[m].0;
                _prod = mul(_prod, &div(x_m, &sub(x_m, &x_j)))
            }
        }

        // y_j * prod
        _prod = mul(yj, &_prod);
        result = add(result, &_prod);
    }

    return result;
}

#[cfg(test)]
mod tests {

    use crate::constants::PARAM_SEED_SIZE;

    use super::*;

    #[test]
    fn shares() {
        let secret = 123_u8;
        let n = 6;
        let coeffs = vec![secret, 166_u8, 94_u8];
        let shares = share_coeffs(coeffs, n);

        assert_eq!(shares.len(), n);
        assert_eq!(
            shares,
            vec![
                (1_u8, 131_u8),
                (2_u8, 79_u8),
                (3_u8, 183_u8),
                (4_u8, 66_u8),
                (5_u8, 186_u8),
                (6_u8, 118_u8),
            ]
        );
    }

    #[test]
    fn reconstructs() {
        let secret = 123_u8;
        let shares1 = vec![(1_u8, 131_u8), (2_u8, 79_u8), (3_u8, 183_u8)];
        let shares2 = vec![(4_u8, 66_u8), (5_u8, 186_u8), (6_u8, 118_u8)];

        let result = reconstruct(&shares1);
        assert_eq!(result, secret);

        let result = reconstruct(&shares2);
        assert_eq!(result, secret);

        // Too few shares
        let shares3 = vec![(1_u8, 131_u8), (2_u8, 79_u8)];

        let result = reconstruct(&shares3);
        assert_ne!(result, secret);
    }

    #[test]
    fn integration() {
        let secret = 123_u8;
        let n = 4;
        let k = 4;
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);

        let shares = share(&secret, n, k, &mut prg);
        let result = reconstruct(&shares);

        assert_eq!(result, secret);

        // Too few shares
        let n = 3;
        let shares = share(&secret, n, k, &mut prg);
        let result = reconstruct(&shares);

        assert_ne!(result, secret);
    }
}
