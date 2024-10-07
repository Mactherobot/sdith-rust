use super::params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE};

pub(crate)type Hash = [u8; PARAM_DIGEST_SIZE];
pub(crate)type Seed = [u8; PARAM_SEED_SIZE];
pub(crate)type Salt = [u8; PARAM_SALT_SIZE];

pub(crate)type CommitmentsArray = [Hash; PARAM_N as usize];
