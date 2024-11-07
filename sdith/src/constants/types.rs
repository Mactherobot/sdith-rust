use super::params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE};

pub(crate) fn hash_default() -> Hash {
    [0u8; PARAM_DIGEST_SIZE]
}

pub type Hash = [u8; PARAM_DIGEST_SIZE];
pub type Seed = [u8; PARAM_SEED_SIZE];
pub type Salt = [u8; PARAM_SALT_SIZE];

pub type CommitmentsArray = [Hash; PARAM_N as usize];
