use super::params::{PARAM_DIGEST_SIZE, PARAM_NB_PARTIES};

pub type Hash = [u8; PARAM_DIGEST_SIZE];

pub type CommitmentsArray = [Hash; PARAM_NB_PARTIES as usize];
