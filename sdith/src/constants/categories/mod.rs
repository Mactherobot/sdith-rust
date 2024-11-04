use crate::arith::gf256::gf256_poly::gf256_evaluate_polynomial_horner;

pub mod cat1;

pub trait Params {
    // SD Parameters
    /// (q) The Galois field size GL(q) = GL(2^8) = GL(256)
    const PARAM_Q: usize;
    /// Code length PARAM_CODE_LENGTH
    const PARAM_M: usize;
    /// Vector dimension PARAM_CODE_DIMENSION
    const PARAM_K: usize;
    /// The Hamming weight bound PARAM_CODE_WEIGHT
    const PARAM_W: usize;
    /// m - k
    const PARAM_M_SUB_K: usize = Self::PARAM_M - Self::PARAM_K;

    // MPC Parameters
    /// (t) Number of random evaluation points
    const PARAM_T: usize;
    /// (η) F_point size for F_point = F_(q^η)
    const PARAM_ETA: usize;

    // MPCitH Parameters
    /// (λ) Security parameter. E.g. used for the 2λ bit salt for commitments
    const PARAM_LAMBDA: usize = Self::PARAM_Q / 2;
    /// (N) Number of secret parties = q
    const PARAM_N: usize = Self::PARAM_Q;
    /// (log_2(N)) Number of log2(nb_parties) for the number of parties
    const PARAM_LOG_N: usize;
    /// (τ) Number of repetitions of the protocol
    const PARAM_TAU: usize;
    /// (ℓ) Privacy threshold (number of open parties)
    const PARAM_L: usize;
    const PARAM_TREE_NB_MAX_OPEN_LEAVES: usize;

    // Signature Parameters
    const PARAM_SEED_SIZE: usize;
    const PARAM_SALT_SIZE: usize;
    const PARAM_DIGEST_SIZE: usize;

    /// d-split variable for the splitting variant of the Syndrome Decoding Problem. Currently set to 1. Should ideally be able to set on running the application and running instances in parallel.
    /// Checkout: Splitting syndrome decoding in the specs
    const PARAM_SPLITTING_FACTOR: usize;

    /// Chunk size for the splitting variant of the Syndrome Decoding Problem for Code Length m
    const PARAM_CHUNK_M: usize = Self::PARAM_M / Self::PARAM_SPLITTING_FACTOR;
    /// Chunk size for the splitting variant of the Syndrome Decoding Problem for Hamming weight w
    const PARAM_CHUNK_W: usize = Self::PARAM_W / Self::PARAM_SPLITTING_FACTOR;

    // Weird params from spec, TODO remove?
    const PARAM_M_SUB_K_CEIL32: usize = ((Self::PARAM_M_SUB_K + 31) >> 5) << 5;
    const PARAM_M_CEIL32: usize = ((Self::PARAM_M + 31) >> 5) << 5;

    // ---------- Serialization Parameters ----------

    // Broadcast Parameters
    const BROADCAST_VALUE_PLAIN_SIZE: usize =
        Self::PARAM_ETA * Self::PARAM_T * Self::PARAM_SPLITTING_FACTOR;
    const BROADCAST_PLAIN_SIZE: usize =
        Self::PARAM_ETA * Self::PARAM_T * Self::PARAM_SPLITTING_FACTOR * 2;
    const BROADCAST_V_PLAIN_SIZE: usize = Self::PARAM_ETA * Self::PARAM_T;

    const BROADCAST_SHARE_PLAIN_SIZE_AB: usize =
        Self::PARAM_ETA * Self::PARAM_T * Self::PARAM_SPLITTING_FACTOR * 2;
    const BROADCAST_SHARE_PLAIN_SIZE_V: usize = Self::PARAM_ETA * Self::PARAM_T;
    const BROADCAST_SHARE_PLAIN_SIZE: usize =
        Self::BROADCAST_SHARE_PLAIN_SIZE_AB + Self::BROADCAST_SHARE_PLAIN_SIZE_V;

    // Beaver Triple Parameters
    /// (t * 2d)η
    const BEAVER_ABPLAIN_SIZE: usize =
        Self::PARAM_ETA * Self::PARAM_T * Self::PARAM_SPLITTING_FACTOR * 2;
    /// tη
    const BEAVER_CPLAIN_SIZE: usize = Self::PARAM_ETA * Self::PARAM_T;
}

pub trait Precomputed<P: Params>
where
    [(); P::PARAM_M + 1]:,
{
    /// Coefficient of polynomial with all factors
    const PRECOMPUTED_F_POLY: [u8; P::PARAM_M + 1];
    /// Leading Coefficients for Lagrangian Polynomials
    const PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S: [u8; P::PARAM_M];
}

pub(self) fn test_f_is_well_formed<P>()
where
    P: Params + Precomputed<P>,
    [(); P::PARAM_M + 1]:,
{
    // We check if the precomputed polynomial F is well-computed
    for i in 0..P::PARAM_CHUNK_M {
        let f_eval = gf256_evaluate_polynomial_horner(&P::PRECOMPUTED_F_POLY, i as u8);
        assert!(
            f_eval == 0,
            "Error: Wrong F evaluation ({}, {}).",
            i,
            f_eval
        );
    }
}
