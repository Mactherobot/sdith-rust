/// Security parameter. E.g. used for the 2λ bit salt for commitments
pub const LAMBDA: u8 = 128;

/// Hash size in bits
pub const HASH_SIZE: usize = 2 * LAMBDA as usize;

/// Byte size of the commitment salt
pub const COMMITMENT_SALT_SIZE: usize = 2 * LAMBDA as usize / 8;
