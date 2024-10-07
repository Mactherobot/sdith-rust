use crate::{
    arith::gf256::gf256_ext::FPoint,
    constants::{
        params::{PARAM_SPLITTING_FACTOR, PARAM_T},
        types::Hash,
    },
    subroutines::prg::prg::PRG,
};

/// Challenge pair `(r, e) ∈ F_point^t, (F_point^t)^d`
#[derive(Clone)]
pub(crate) struct Challenge {
    pub(crate) r: [FPoint; PARAM_T],
    pub(crate) e: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR],
}

impl Challenge {
    /// Generate `number_of_pairs` of challenges (r, e) ∈ F_point^t, (F_point^t)^d
    /// Uses h1 hash for Fiat-Shamir Transform
    pub(crate) fn new(h1: Hash) -> Self {
        let mut prg = PRG::init_base(&h1);
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
        Self::new(Hash::default())
    }
}

#[cfg(test)]
mod challenge_tests {
    use crate::constants::params::PARAM_ETA;

    use super::*;

    #[test]
    fn test_generate() {
        let hash = Hash::default();
        let challenge = Challenge::new(hash);
        assert_eq!(challenge.r.len(), PARAM_T);
        assert_eq!(challenge.e.len(), PARAM_SPLITTING_FACTOR);
        for r in challenge.r.iter() {
            assert_eq!(r.len(), PARAM_ETA);
        }
    }
}
