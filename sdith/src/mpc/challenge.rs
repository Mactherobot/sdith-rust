use crate::{
    arith::gf256::gf256_ext::FPoint,
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::prg::{hashing::HASH_PREFIX_CHALLENGE_1, prg::PRG},
};

/// Amount t*(d+1) of FPoint elements in a challenge (r, e) ∈ F_point^t, (F_point^t)^d
const ChallengePointLength: usize = PARAM_T * (PARAM_SPLITTING_FACTOR + 1);

/// Challenge pair `(r, e) ∈ F_point^t, (F_point^t)^d`
pub(super) struct Challenge {
    r: [FPoint; PARAM_T],
    e: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR],
}

impl Challenge {
    /// Generate `number_of_pairs` of challenges (r, e) ∈ F_point^t, (F_point^t)^d
    /// Uses h1 hash for Fiat-Shamir Transform
    pub(super) fn generate_n(n: usize) -> Vec<Challenge> {
        let mut prg = PRG::init_base(&HASH_PREFIX_CHALLENGE_1);
        let mut challenges = Vec::<Challenge>::with_capacity(n);

        // Loop to generate challenges
        for _ in 0..n {
            let challenge_point_elements =
                prg.sample_field_f_point_elements::<ChallengePointLength>();
            challenges.push(Challenge::parse(challenge_point_elements));
        }

        challenges
    }

    /// Parse a slice of FPoint elements into a Challenge struct
    fn parse(src: [FPoint; ChallengePointLength]) -> Self {
        let r: [FPoint; PARAM_T] = src[..PARAM_T].try_into().expect("Failed to parse r");

        let mut e: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR] = Default::default();
        for d in 0..(PARAM_SPLITTING_FACTOR) {
            e[d] = src[((d + 1) * PARAM_T)..((d + 2) * PARAM_T)]
                .try_into()
                .expect("Failed to parse e");
        }

        Challenge { r, e }
    }
}

#[cfg(test)]
mod challenge_tests {
    use super::*;

    #[test]
    fn test_parse() {
        let mut prg = PRG::init_base(&HASH_PREFIX_CHALLENGE_1);
        let points = prg.sample_field_f_point_elements::<ChallengePointLength>();

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
        let challenges = Challenge::generate_n(2);
        assert_eq!(challenges.len(), 2);
    }
}
