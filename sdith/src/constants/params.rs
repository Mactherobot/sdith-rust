// SD Parameters
/// Also called q in the spec and is the Galois field size GL(q) = GL(2^8) = GL(256)
pub(crate) const PARAM_FIELD_SIZE: usize = 256;
/// Also called m in the spec
pub(crate) const PARAM_M: usize = 230;
/// Also called k in the spec
pub(crate) const PARAM_K: usize = 126;
/// Also called w in the spec and is the Hamming weight bound
pub(crate) const PARAM_W: usize = 79;
/// m - k
pub(crate) const PARAM_M_SUB_K: usize = PARAM_M - PARAM_K;

// MPC Parameters
pub(crate) const PARAM_NB_EVALS_PER_POLY: usize = 7;
pub(crate) const PARAM_EXT_DEGREE: usize = 4;

// MPCitH Parameters
/// Security parameter. E.g. used for the 2λ bit salt for commitments
pub(crate) const PARAM_LAMBDA: usize = PARAM_FIELD_SIZE / 2;
/// Number of secret parties
pub(crate) const PARAM_NB_PARTIES: usize = PARAM_FIELD_SIZE;
/// Number of log2(nb_parties) for the number of parties
pub(crate) const PARAM_LOG_NB_PARTIES: usize = 8;
/// Number of repetitions of the protocol
pub(crate) const PARAM_NB_EXECUTIONS: usize = 6;
pub(crate) const PARAM_NB_REVEALED: usize = 3;
pub(crate) const PARAM_TREE_NB_MAX_OPEN_LEAVES: usize = 19;

// Signature Parameters
pub(crate) const PARAM_SEED_SIZE: usize = 128 / 8;
pub(crate) const PARAM_SALT_SIZE: usize = 256 / 8;
pub(crate) const PARAM_DIGEST_SIZE: usize = 256 / 8;

/// d-split variable for the splitting variant of the Syndrome Decoding Problem. Currently set to 1. Should ideally be able to set on running the application and running instances in parallel.
/// Checkout: Splitting syndrome decoding in the specs
pub(crate) const PARAM_SPLITTING_FACTOR: usize = 1;

pub(crate) const PARAM_CHUNK_LENGTH: usize = PARAM_M / PARAM_SPLITTING_FACTOR;
pub(crate) const PARAM_CHUNK_WEIGHT: usize = PARAM_W / PARAM_SPLITTING_FACTOR;
