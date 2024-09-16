use crate::constants::{PARAM_PUBLIC_KEY_BYTES, PARAM_SECRET_KEY_BYTES};

pub(crate) type PublicKey = [u8; PARAM_PUBLIC_KEY_BYTES];
pub(crate) type SecretKey = [u8; PARAM_SECRET_KEY_BYTES];
