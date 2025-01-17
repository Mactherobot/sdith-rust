use super::{Categories, HashPrimitive, XOFPrimitive, PARAM_CHUNK_M};

// Environment
pub(super) const COMPILED_CATEGORY: Categories = Categories::THREE;
pub(super) const XOF_PRIMITIVE: XOFPrimitive = XOFPrimitive::SHAKE256;
pub(super) const HASH_PRIMITIVE: HashPrimitive = HashPrimitive::SHA3_384;

// SD Parameters
pub(super) const PARAM_Q: usize = 256;
pub(super) const PARAM_M: usize = 376;
pub(super) const PARAM_K: usize = 220;
pub(super) const PARAM_W: usize = 114;
pub(super) const PARAM_SPLITTING_FACTOR: usize = 2;

// MPCitH Parameters
pub(super) const PARAM_N: usize = 256;
pub(super) const PARAM_L: usize = 3;
pub(super) const PARAM_TAU: usize = 9;
pub(super) const PARAM_ETA: usize = 4;
pub(super) const PARAM_T: usize = 10;

// Signature Parameters
pub(super) const PARAM_SEED_SIZE: usize = 192;
pub(super) const PARAM_SALT_SIZE: usize = 384;
pub(super) const PARAM_DIGEST_SIZE: usize = 384;

// Precomputed constants
pub const PRECOMPUTED_F_POLY: [u8; PARAM_CHUNK_M + 1] = [
    0, 197, 158, 11, 89, 79, 116, 248, 234, 125, 162, 193, 110, 120, 135, 229, 145, 67, 35, 245,
    81, 162, 173, 168, 224, 59, 59, 88, 228, 149, 153, 152, 199, 118, 86, 103, 109, 15, 20, 99,
    240, 223, 208, 50, 30, 184, 219, 64, 126, 171, 197, 89, 248, 188, 87, 233, 208, 45, 134, 215,
    80, 253, 7, 0, 244, 125, 83, 51, 48, 163, 12, 166, 123, 245, 18, 219, 35, 210, 180, 26, 205,
    187, 165, 152, 240, 24, 215, 214, 180, 51, 206, 144, 82, 188, 71, 0, 238, 34, 219, 185, 22, 28,
    78, 204, 19, 12, 108, 138, 213, 166, 93, 0, 31, 73, 128, 70, 176, 106, 145, 0, 196, 44, 215, 0,
    251, 0, 0, 0, 84, 250, 47, 99, 121, 253, 199, 185, 47, 213, 252, 91, 222, 63, 204, 194, 211,
    138, 67, 151, 119, 21, 199, 167, 154, 97, 193, 223, 108, 217, 216, 0, 249, 156, 198, 207, 3,
    47, 15, 101, 21, 193, 147, 29, 92, 27, 26, 0, 212, 66, 49, 120, 24, 126, 127, 0, 18, 6, 7, 0,
    1,
];
pub const PRECOMPUTED_LAGRANGE_INTERPOLATION_WEIGHTS: [u8; PARAM_CHUNK_M] = [
    212, 212, 212, 212, 149, 149, 149, 149, 53, 53, 53, 53, 116, 116, 116, 116, 27, 27, 27, 27, 90,
    90, 90, 90, 250, 250, 250, 250, 187, 187, 187, 187, 193, 193, 193, 193, 128, 128, 128, 128, 32,
    32, 32, 32, 97, 97, 97, 97, 14, 14, 14, 14, 79, 79, 79, 79, 239, 239, 239, 239, 174, 174, 174,
    174, 101, 101, 101, 101, 17, 17, 17, 17, 71, 71, 71, 71, 51, 51, 51, 51, 52, 52, 52, 52, 64,
    64, 64, 64, 22, 22, 22, 22, 98, 98, 98, 98, 136, 136, 136, 136, 252, 252, 252, 252, 170, 170,
    170, 170, 222, 222, 222, 222, 217, 217, 217, 217, 173, 173, 173, 173, 251, 251, 251, 251, 143,
    143, 143, 143, 144, 144, 144, 144, 165, 165, 165, 165, 83, 83, 83, 83, 102, 102, 102, 102, 14,
    14, 14, 14, 59, 59, 59, 59, 205, 205, 205, 205, 248, 248, 248, 248, 104, 104, 104, 104, 93, 93,
    93, 93, 171, 171, 171, 171, 158, 158, 158, 158, 246, 246, 246, 246, 195, 195, 195, 195, 53, 53,
    53, 53,
];
