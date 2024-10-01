use crate::{
    arith::{gf256::gf256_ext::FPoint, vectors::parse_to},
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::prg::{hashing::HASH_PREFIX_CHALLENGE_1, prg::PRG},
};

/// Amount t*(d+1) of FPoint elements in a challenge (r, e) ∈ F_point^t, (F_point^t)^d
const CHALLENGE_POINT_LENGTH: usize = PARAM_T * (PARAM_SPLITTING_FACTOR + 1);

/// Challenge pair `(r, e) ∈ F_point^t, (F_point^t)^d`
pub(super) struct Challenge {
    r: [FPoint; PARAM_T],
    e: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR],
}

type ChallengePlain = [u8; CHALLENGE_POINT_LENGTH * PARAM_ETA];

impl Challenge {
    /// Generate `number_of_pairs` of challenges (r, e) ∈ F_point^t, (F_point^t)^d
    /// Uses h1 hash for Fiat-Shamir Transform
    pub(super) fn generate_plain() -> ChallengePlain {
        let mut prg = PRG::init_base(&HASH_PREFIX_CHALLENGE_1);

        let mut plain_challenge = [0u8; CHALLENGE_POINT_LENGTH * PARAM_ETA];
        prg.sample_field_fq_elements(&mut plain_challenge);
        plain_challenge
    }

    /// Parse a slice of FPoint elements into a Challenge struct
    fn parse(challenge_plain: ChallengePlain) -> Challenge {
        // Split the challenge into points
        let points = [FPoint::default(); CHALLENGE_POINT_LENGTH];
        parse_to(src, dst);
        Challenge { r, e }
    }
}

#[cfg(test)]
mod challenge_tests {
    use crate::constants::params::PARAM_ETA;

    use super::*;

    #[test]
    fn test_parse() {
        let mut prg = PRG::init_base(&HASH_PREFIX_CHALLENGE_1);
        let mut points = [FPoint::default(); CHALLENGE_POINT_LENGTH];
        prg.sample_field_fpoint_elements(&mut points);

        let challenge = Challenge::parse(points);
        assert_eq!(challenge.r.len(), PARAM_T);
        for r in challenge.r {
            assert_eq!(r.len(), PARAM_ETA);
        }
        assert_eq!(challenge.e.len(), PARAM_SPLITTING_FACTOR);
        for e in challenge.e {
            assert_eq!(e.len(), PARAM_T);
            for e_i in e {
                assert_eq!(e_i.len(), PARAM_ETA);
            }
        }
    }

    #[test]
    fn test_generate() {
        let challenges = Challenge::generate_plain(2);
        assert_eq!(challenges.len(), 2);
    }
}
