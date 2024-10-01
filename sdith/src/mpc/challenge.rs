use crate::{
    arith::gf256::gf256_ext::FPoint,
    constants::params::{PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::prg::{hashing::HASH_PREFIX_CHALLENGE_1, prg::PRG},
};

/// Challenge pair `(r, e) ∈ F_point^t, (F_point^t)^d`
pub(crate) struct Challenge {
    pub(crate) r: [FPoint; PARAM_T],
    pub(crate) e: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR],
}

impl Challenge {
    /// Generate `number_of_pairs` of challenges (r, e) ∈ F_point^t, (F_point^t)^d
    /// Uses h1 hash for Fiat-Shamir Transform
    pub(super) fn new() -> Self {
        let mut prg = PRG::init_base(&HASH_PREFIX_CHALLENGE_1);
        let mut r = [FPoint::default(); PARAM_T];
        prg.sample_field_fpoint_elements(&mut r);

        let mut e = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        for e_i in e.iter_mut() {
            prg.sample_field_fpoint_elements(e_i);
        }

        Self { r, e }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod challenge_tests {
    use crate::constants::params::PARAM_ETA;

    use super::*;

    #[test]
    fn test_generate() {
        let challenge = Challenge::new();
        assert_eq!(challenge.r.len(), PARAM_T);
        assert_eq!(challenge.e.len(), PARAM_SPLITTING_FACTOR);
        for r in challenge.r.iter() {
            assert_eq!(r.len(), PARAM_ETA);
        }
    }
}
