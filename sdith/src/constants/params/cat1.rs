use super::{Categories, HashPrimitive, XOFPrimitive};

// Environment
pub(super) const COMPILED_CATEGORY: Categories = Categories::ONE;
pub(super) const XOF_PRIMITIVE: XOFPrimitive = XOFPrimitive::SHAKE128;
pub(super) const HASH_PRIMITIVE: HashPrimitive = HashPrimitive::SHA3_256;

// SD Parameters
pub(super) const PARAM_Q: usize = 256;
pub(super) const PARAM_M: usize = 242;
pub(super) const PARAM_K: usize = 126;
pub(super) const PARAM_W: usize = 87;
pub(super) const PARAM_SPLITTING_FACTOR: usize = 1;

// MPCitH Parameters
pub(super) const PARAM_N: usize = 256;
pub(super) const PARAM_L: usize = 3;
pub(super) const PARAM_TAU: usize = 6;
pub(super) const PARAM_ETA: usize = 4;
pub(super) const PARAM_T: usize = 7;

// Signature Parameters
pub(super) const PARAM_SEED_SIZE: usize = 128;
pub(super) const PARAM_SALT_SIZE: usize = 256;
pub(super) const PARAM_DIGEST_SIZE: usize = 256;

// Precomputed constants
pub const PRECOMPUTED_F_POLY: [u8; 243] = [
    0, 236, 238, 23, 164, 169, 114, 156, 211, 182, 70, 113, 128, 254, 46, 57, 236, 121, 249, 249,
    101, 129, 184, 110, 158, 168, 119, 107, 167, 171, 122, 175, 35, 209, 242, 154, 83, 189, 10,
    193, 169, 30, 84, 154, 220, 116, 27, 161, 166, 57, 122, 244, 61, 59, 20, 184, 0, 91, 240, 182,
    9, 140, 140, 0, 150, 76, 241, 195, 44, 116, 148, 106, 180, 31, 205, 48, 197, 46, 231, 74, 208,
    236, 208, 152, 159, 36, 254, 155, 199, 63, 77, 126, 108, 206, 206, 0, 66, 112, 196, 45, 92,
    183, 43, 239, 204, 80, 225, 4, 119, 143, 143, 0, 204, 205, 137, 204, 38, 225, 225, 0, 24, 44,
    44, 0, 0, 0, 0, 0, 49, 79, 122, 185, 125, 43, 139, 116, 197, 114, 250, 112, 118, 65, 54, 68,
    96, 118, 86, 225, 185, 245, 209, 140, 198, 173, 165, 103, 27, 237, 237, 0, 216, 138, 2, 10,
    185, 45, 241, 246, 192, 217, 172, 19, 176, 162, 162, 0, 115, 218, 26, 194, 184, 213, 213, 0,
    12, 22, 22, 0, 0, 0, 0, 0, 69, 192, 114, 103, 0, 73, 198, 62, 21, 44, 38, 48, 152, 11, 11, 0,
    167, 100, 136, 41, 11, 180, 180, 0, 120, 156, 156, 0, 0, 0, 0, 0, 194, 98, 11, 39, 34, 129,
    129, 0, 218, 167, 167, 0, 0, 0, 0, 0, 182, 1, 1,
];
pub const PRECOMPUTED_LAGRANGE_INTERPOLATION_WEIGHTS: [u8; 242] = [
    93, 93, 214, 214, 169, 169, 228, 228, 45, 45, 171, 171, 22, 22, 33, 33, 56, 56, 108, 108, 55,
    55, 128, 128, 68, 68, 93, 93, 220, 220, 81, 81, 73, 73, 106, 106, 51, 51, 20, 20, 188, 188,
    167, 167, 117, 117, 29, 29, 239, 239, 145, 145, 202, 202, 149, 149, 191, 191, 185, 185, 113,
    113, 33, 33, 65, 65, 160, 160, 177, 177, 14, 14, 50, 50, 114, 114, 247, 247, 158, 158, 49, 49,
    107, 107, 243, 243, 210, 210, 218, 218, 97, 97, 117, 117, 194, 194, 181, 181, 135, 135, 87, 87,
    249, 249, 205, 205, 107, 107, 102, 102, 43, 43, 215, 215, 220, 220, 163, 163, 17, 17, 158, 158,
    65, 65, 251, 251, 234, 234, 117, 117, 89, 89, 46, 46, 10, 10, 52, 52, 182, 182, 198, 198, 59,
    59, 196, 196, 103, 103, 124, 124, 242, 242, 130, 130, 207, 207, 203, 203, 220, 220, 58, 58, 91,
    91, 3, 3, 168, 168, 242, 242, 8, 8, 30, 30, 89, 89, 147, 147, 255, 255, 237, 237, 110, 110,
    245, 245, 66, 66, 6, 6, 41, 41, 33, 33, 9, 9, 38, 38, 158, 158, 107, 107, 65, 65, 63, 63, 242,
    242, 166, 166, 101, 101, 139, 139, 253, 253, 127, 127, 254, 254, 89, 89, 26, 26, 57, 57, 39,
    39, 192, 192, 140, 140, 116, 116, 93, 93, 162, 162, 174, 174, 119, 119,
];
