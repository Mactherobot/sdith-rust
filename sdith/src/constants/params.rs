// SD Parameters
/// Also called q in the spec and is the Galois field size GL(q) = GL(2^8) = GL(256)
pub(crate) const PARAM_FIELD_SIZE: usize = 256;
/// Also called m in the spec
pub(crate) const PARAM_CODE_LENGTH: usize = 230;
/// Also called k in the spec
pub(crate) const PARAM_CODE_DIMENSION: usize = 126;
/// Also called w in the spec and is the Hamming weight bound
pub(crate) const PARAM_CODE_WEIGHT: usize = 79;

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
// TODO:  pub(crate) const PARAM_SIGNATURE_SIZEBYTES = 2*PARAM_DIGEST_SIZE + PARAM_SALT_SIZE + PARAM_COMPRESSED_BR_SIZE + PARAM_NB_EXECUTIONS*PARAM_NB_REVEALED * (PARAM_WIT_SHORT_SIZE + PARAM_CORR_SHORT_SIZE + PARAM_UNIF_SHORT_SIZE) + PARAM_NB_EXECUTIONS*PARAM_DIGEST_SIZE * PARAM_TREE_NB_MAX_OPEN_LEAVES;


// Witness (witness.h)
pub(crate) const PARAM_INSTANCE_SIZE: usize = PARAM_SEED_SIZE + PARAM_SYNDROME_LENGTH;
pub(crate) const PARAM_SOL_SIZE: usize =
    PARAM_CODE_DIMENSION + 2 * PARAM_SPLITTING_FACTOR * PARAM_CHUNK_WEIGHT;

// Keygen (keygen.h)
pub(crate) const PARAM_PUBLIC_KEY_BYTES: usize = PARAM_INSTANCE_SIZE;
pub(crate) const PARAM_SECRET_KEY_BYTES: usize = PARAM_SEED_SIZE + PARAM_SOL_SIZE;
pub(crate) const PARAM_SECRET_KEY_BYTES_SHORT: usize = PARAM_SEED_SIZE;

// Misc
pub(crate) const PARAM_SPLITTING_FACTOR: usize = 1;
pub(crate) const PARAM_CHUNK_LENGTH: usize = PARAM_CODE_LENGTH / PARAM_SPLITTING_FACTOR;
pub(crate) const PARAM_CHUNK_WEIGHT: usize = PARAM_CODE_WEIGHT / PARAM_SPLITTING_FACTOR;

pub(crate) const PARAM_SYNDROME_LENGTH: usize = PARAM_CODE_LENGTH - PARAM_CODE_DIMENSION;
pub(crate) const PARAM_SYNDROME_LENGTH_CEIL32: usize = ((PARAM_SYNDROME_LENGTH + 31) >> 5) << 5;
pub(crate) const PARAM_CODEWORD_LENGTH: usize = PARAM_CODE_LENGTH;
pub(crate) const PARAM_CODEWORD_LENGTH_CEIL32: usize = ((PARAM_CODEWORD_LENGTH + 31) >> 5) << 5;
pub(crate) const PARAM_PLAINTEXT_LENGTH: usize = PARAM_CODE_DIMENSION;
pub(crate) const PARAM_PCMATRIX_BYTESIZE: usize =
    PARAM_CODE_DIMENSION * PARAM_SYNDROME_LENGTH_CEIL32;

