use super::params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE};

pub type Hash = Vec<u8>; // Vector of size `PARAM_DIGEST_SIZE`
pub type Seed = Vec<u8>; // Vector of size `PARAM_SEED_SIZE`
pub type Salt = Vec<u8>; // Vector of size `PARAM_SALT_SIZE`

pub type CommitmentsArray = Vec<Hash>;
