use crypto_bigint::{rand_core::OsRng, NonZero, RandomMod, U256};

use crate::modular_arithmetics::{div_mod, evaluate_polynomial, mul_mod};

/// Share a secret `v` among `n` parties using Shamir's secret sharing scheme.
///
/// Given an integer valued data `v`, we
/// pick a prime p which is bigger than both `v` and `n`
pub(crate) fn share(v: &U256, prime: &NonZero<U256>, n: usize, k: usize) -> Vec<(U256, U256)> {
    // Generate a random polynomial of degree `k - 1` with the constant term `v`.
    // Coefficients are chosen uniformly at random from the field `Z_p`.
    let mut coefficients: Vec<U256> = Vec::with_capacity(k);
    coefficients.push(v.clone());
    for _ in 1..k {
        let r = U256::random_mod(&mut OsRng, &prime);
        coefficients.push(r);
    }

    share_coeffs(coefficients, prime, n)
}

fn share_coeffs(coefficients: Vec<U256>, prime: &NonZero<U256>, n: usize) -> Vec<(U256, U256)> {
    // Evaluate the polynomial at `n` distinct points in the field `Z_p`.
    let mut shares: Vec<(U256, U256)> = Vec::with_capacity(n);
    assert!(n < u32::MAX as usize);
    for i in 1..=n {
        let x = U256::from(i as u32);
        let y = evaluate_polynomial(&coefficients, &x, prime);
        shares.push((x, y));
    }

    return shares;
}

pub(crate) fn reconstruct(shares: &Vec<(U256, U256)>, prime: &U256) -> U256 {
    let mut result = U256::ZERO;
    let k = shares.len();
    for j in 0..k {
        let (x_j, yj) = shares[j];

        // prod = Π_{m=0}^{threshold-1} m != j (x_m / (x_m - x_j))
        let mut _prod = U256::ONE;
        for m in 0..k {
            if m != j {
                let x_m = shares[m].0;
                _prod = mul_mod(
                    &_prod,
                    &div_mod(&x_m, &x_m.sub_mod(&x_j, prime), prime),
                    prime,
                )
            }
        }

        // y_j * prod
        result = result.add_mod(&mul_mod(&yj, &_prod, prime), prime);
    }

    return result;
}

#[cfg(test)]
mod tests {

    use crate::u256_to_u64;

    use super::*;

    #[test]
    fn shares() {
        let secret = U256::from(1234 as u32);
        let n = 6;
        let prime = NonZero::<U256>::new(U256::from(1613 as u32)).unwrap();
        let coeffs = vec![secret, U256::from(166 as u32), U256::from(94 as u32)];

        let shares = share_coeffs(coeffs, &prime, n);

        assert_eq!(shares.len(), n);
        assert_eq!(
            shares,
            vec![
                (U256::from(1 as u32), U256::from(1494 as u32)),
                (U256::from(2 as u32), U256::from(329 as u32)),
                (U256::from(3 as u32), U256::from(965 as u32)),
                (U256::from(4 as u32), U256::from(176 as u32)),
                (U256::from(5 as u32), U256::from(1188 as u32)),
                (U256::from(6 as u32), U256::from(775 as u32)),
            ]
        );
    }

    #[test]
    fn reconstructs() {
        let secret = U256::from(1234 as u32);
        let prime = U256::from(1613 as u32);
        let shares1 = vec![
            (U256::from(1 as u32), U256::from(1494 as u32)),
            (U256::from(2 as u32), U256::from(329 as u32)),
            (U256::from(3 as u32), U256::from(965 as u32)),
        ];

        let shares2 = vec![
            (U256::from(4 as u32), U256::from(176 as u32)),
            (U256::from(5 as u32), U256::from(1188 as u32)),
            (U256::from(6 as u32), U256::from(775 as u32)),
        ];

        let result = reconstruct(&shares1, &prime);
        assert_eq!(u256_to_u64!(result), u256_to_u64!(secret));

        let result = reconstruct(&shares2, &prime);
        assert_eq!(u256_to_u64!(result), u256_to_u64!(secret));

        // Too few shares
        let shares3 = vec![
            (U256::from(1 as u32), U256::from(1494 as u32)),
            (U256::from(2 as u32), U256::from(329 as u32)),
        ];

        let result = reconstruct(&shares3, &prime);
        assert_ne!(u256_to_u64!(result), u256_to_u64!(secret));
    }

    #[test]
    fn integration() {
        let secret = U256::from(1234 as u32);
        let n = 4;
        let k = 4;
        let prime = NonZero::<U256>::new(U256::from(1613 as u32)).unwrap();

        let shares = share(&secret, &prime, n, k);
        let result = reconstruct(&shares, &prime);

        assert_eq!(u256_to_u64!(result), u256_to_u64!(secret));

        // Too few shares
        let n = 3;
        let shares = share(&secret, &prime, n, k);
        let result = reconstruct(&shares, &prime);

        assert_ne!(u256_to_u64!(result), u256_to_u64!(secret));
    }
}
