// SD Parameters
/// (q) The Galois field size GL(q) = GL(2^8) = GL(256)
pub(crate) const PARAM_Q: usize = 256;
/// Code length PARAM_CODE_LENGTH
pub(crate) const PARAM_M: usize = 242;
/// Vector dimension PARAM_CODE_DIMENSION
pub(crate) const PARAM_K: usize = 126;
/// The Hamming weight bound PARAM_CODE_WEIGHT
pub(crate) const PARAM_W: usize = 87;
/// m - k
pub(crate) const PARAM_M_SUB_K: usize = PARAM_M - PARAM_K;

// MPC Parameters
/// (t) Number of random evaluation points
pub(crate) const PARAM_T: usize = 7;
/// (η) F_point size for F_point = F_(q^η)
pub(crate) const PARAM_ETA: usize = 4;

// MPCitH Parameters
/// (λ) Security parameter. E.g. used for the 2λ bit salt for commitments
pub(crate) const PARAM_LAMBDA: usize = PARAM_Q / 2;
/// (N) Number of secret parties = q
pub(crate) const PARAM_N: usize = PARAM_Q;
/// (log_2(N)) Number of log2(nb_parties) for the number of parties
pub(crate) const PARAM_LOG_N: usize = 8;
/// (τ) Number of repetitions of the protocol
pub(crate) const PARAM_TAU: usize = 6;
/// (ℓ) Privacy threshold (number of open parties)
pub(crate) const PARAM_L: usize = 3;
pub(crate) const PARAM_TREE_NB_MAX_OPEN_LEAVES: usize = 19;

// Signature Parameters
pub const PARAM_SEED_SIZE: usize = 128 / 8;
pub const PARAM_SALT_SIZE: usize = 256 / 8;
pub const PARAM_DIGEST_SIZE: usize = 256 / 8;

/// d-split variable for the splitting variant of the Syndrome Decoding Problem. Currently set to 1. Should ideally be able to set on running the application and running instances in parallel.
/// Checkout: Splitting syndrome decoding in the specs
pub(crate) const PARAM_SPLITTING_FACTOR: usize = 1;

/// Chunk size for the splitting variant of the Syndrome Decoding Problem for Code Length m
pub(crate) const PARAM_CHUNK_M: usize = PARAM_M / PARAM_SPLITTING_FACTOR;
/// Chunk size for the splitting variant of the Syndrome Decoding Problem for Hamming weight w
pub(crate) const PARAM_CHUNK_W: usize = PARAM_W / PARAM_SPLITTING_FACTOR;

// Weird params from spec, TODO remove?
pub(crate) const PARAM_M_SUB_K_CEIL32: usize = ((PARAM_M_SUB_K + 31) >> 5) << 5;
pub(crate) const PARAM_M_CEIL32: usize = ((PARAM_M + 31) >> 5) << 5;
