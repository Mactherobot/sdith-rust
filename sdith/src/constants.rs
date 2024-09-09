// SD Parameters
pub const PARAM_FIELD_SIZE: usize = 256;
/// Security parameter. E.g. used for the 2λ bit salt for commitments
pub const PARAM_LAMBDA: usize = PARAM_FIELD_SIZE / 2;
pub const PARAM_CODE_LENGTH: usize = 230;
pub const PARAM_CODE_DIMENSION: usize = 126;
pub const PARAM_CODE_WEIGHT: usize = 79;

// MPC Parameters
pub const PARAM_NB_EVALS_PER_POLY: usize = 7;
pub const PARAM_EXT_DEGREE: usize = 4;

// MPCitH Parameters
pub const PARAM_NB_PARTIES: usize = PARAM_FIELD_SIZE;
pub const PARAM_LOG_NB_PARTIES: usize = 8;
pub const PARAM_NB_EXECUTIONS: usize = 6;
pub const PARAM_NB_REVEALED: usize = 3;
pub const PARAM_TREE_NB_MAX_OPEN_LEAVES: usize = 19;

// Signature Parameters
pub const PARAM_SEED_SIZE: usize = 128 / 8;
pub const PARAM_SALT_SIZE: usize = 256 / 8;
pub const PARAM_DIGEST_SIZE: usize = 256 / 8;

/// Hash size in bits
pub const PARAM_HASH_BIT_SIZE: usize = PARAM_FIELD_SIZE;
pub type Hash = [u8; PARAM_DIGEST_SIZE];
pub type CommitmentsArray = [Hash; PARAM_NB_PARTIES as usize];
