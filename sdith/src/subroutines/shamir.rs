use crate::{arith::gf256::FieldArith, constants::params::PARAM_L};

use super::prg::prg::PRG;

/// Shamir's secret sharing scheme with a fixed threshold `K`.
pub(crate) trait Shamir<const K: usize>
where
    Self: Sized + FieldArith + Default + Copy + Clone,
{
    /// Computes `n` shares of a secret `v` using Shamir's secret sharing scheme.
    fn share(&self, n: usize, prg: &mut PRG) -> Vec<(Self, Self)>
    where
        [(); K - 1]:,
    {
        // Generate a random polynomial of degree `k - 1` with the constant term `v`.
        // Coefficients are chosen uniformly at random from the field `GF256`.
        let mut coefficients = [Self::default(); PARAM_L];
        coefficients[0] = self.clone();
        coefficients[1..].copy_from_slice(&Self::sample_field_elements(prg));

        let mut shares: Vec<(Self, Self)> = Vec::with_capacity(n);
        assert!(n < u8::MAX as usize);
        for i in 1..=n {
            let x: Self = Self::from_usize(i);
            let y = Self::field_eval_polynomial(&x, &coefficients);
            shares.push((x, y));
        }

        return shares;
    }

    /// Reconstructs the secret from `k` shares into self.
    fn reconstruct(shares: [(Self, Self); K]) -> Self {
        let mut res = Self::field_zero();
        for j in 0..K {
            let (x_j, yj) = shares[j];

            // prod = Π_{m=0}^{threshold-1} m != j (x_m / (x_m - x_j))
            let mut _prod = Self::field_one();
            for m in 0..K {
                if m != j {
                    let x_m = shares[m].0;
                    _prod.field_mul_mut(Self::field_div(&x_m, Self::field_sub(&x_m, x_j)));
                }
            }

            // y_j * prod
            _prod.field_mul_mut(yj);
            res.field_add_mut(_prod);
        }
        res
    }
    /// For sampling elements to create share
    fn sample_field_elements(prg: &mut PRG) -> [Self; K - 1];
    fn from_usize(x: usize) -> Self;
}

#[cfg(test)]
mod test_fq_shamir {
    use crate::{
        constants::params::{PARAM_L, PARAM_SEED_SIZE},
        subroutines::{prg::prg::PRG, shamir::Shamir},
    };

    #[test]
    fn shares() {
        let secret = 123_u8;
        let n = 6;
        let shares = secret.share(n, &mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));

        assert_eq!(shares.len(), n);
        assert_eq!(
            shares,
            vec![(1, 222), (2, 17), (3, 180), (4, 67), (5, 230), (6, 41)]
        );
    }

    #[test]
    fn reconstructs() {
        let secret = 123_u8;
        let shares1 = [(1, 222), (2, 17), (3, 180)];
        let shares2 = [(4, 67), (5, 230), (6, 41)];

        let result = u8::reconstruct(shares1);
        assert_eq!(result, secret);

        let result = u8::reconstruct(shares2);
        assert_eq!(result, secret);
    }

    #[test]
    fn integration() {
        let secret = 123_u8;
        let n = PARAM_L;
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], None);

        let shares = secret.share(n, &mut prg);
        let result = u8::reconstruct(shares.try_into().unwrap());

        assert_eq!(result, secret);
    }
}
