use const_gen::*;
use std::{env, fs, path::Path};

fn main() {
    // Load the environment variables from the .env file
    let cat = get_category();

    // Use the OUT_DIR environment variable to get an
    // appropriate path.
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let constants_file_path = Path::new(&out_dir).join("const_gen.rs");
    let precomputed_file_path = Path::new(&out_dir).join("precomputed_gen.rs");

    println!(
        "cargo:warning=Generating constants for category {:?}",
        cat.category
    );

    // Check if feature flag is blake3 as it is not supported for categories above 1
    if (cfg!(feature = "xof_blake3") || cfg!(feature = "hash_blake3"))
        && cat.category != Categories::ONE
    {
        panic!("Blake3 only supports 128 bit security. 256 is required for categories above 1.")
    }

    // Lastly, output to the destination file.
    fs::write(&constants_file_path, build_constants(cat)).unwrap();
    fs::write(&precomputed_file_path, cat.precomputed.output()).unwrap();

    println!("cargo::rerun-if-env-changed=SDITH_CATEGORY");
}

fn get_feature_flag_category() -> Result<Category, String> {
    if cfg!(feature = "category_one") {
        Ok(CATEGORY_ONE)
    } else if cfg!(feature = "category_three") {
        Ok(CATEGORY_THREE)
    } else if cfg!(feature = "category_five") {
        Ok(CATEGORY_FIVE)
    } else {
        Err("No category feature flag set".to_string())
    }
}


fn get_category() -> Category {

    // Check feature flags
    match get_feature_flag_category() {
        Ok(cat) => return cat,
        Err(_) => (),
    }

    // Check environment variable
    let category = env::var("SDITH_CATEGORY").unwrap_or_else(|_| "ONE".to_string());
    match Categories::from(category) {
        Categories::ONE => CATEGORY_ONE,
        Categories::THREE => CATEGORY_THREE,
        Categories::FIVE => CATEGORY_FIVE,
    }
}

fn build_constants(category: Category) -> String {
    vec![
        "#[derive(Debug)] #[doc = \"Compiled version category of the protocol\"] pub enum Categories { ONE = 1, THREE = 3, FIVE = 5 }".to_string(),
        const_declaration!(#[doc = "Compiled category for the protocol"] pub(crate) COMPILED_CATEGORY = category.category),

        const_definition!(#[derive(Debug)] pub HashPrimitive),
        const_definition!(#[derive(Debug)] pub XOFPrimitive),

        "// SD Parameters".to_string(),
        const_declaration!(#[doc = "(q) The Galois field size GL(q) = GL(2^8) = GL(256)"] pub(crate) PARAM_Q = category.sd_param_q),
        const_declaration!(#[doc = "Code length PARAM_CODE_LENGTH"] pub(crate) PARAM_M = category.sd_param_m),
        const_declaration!(#[doc = "Vector dimension PARAM_CODE_DIMENSION"] pub(crate) PARAM_K = category.sd_param_k),
        const_declaration!(#[doc = "The Hamming weight bound PARAM_CODE_WEIGHT"] pub(crate) PARAM_W = category.sd_param_w),
        const_declaration!(#[doc = "Splitting factor for the syndrome variant"] pub(crate) PARAM_SPLITTING_FACTOR = category.sd_param_splitting_factor),
        
        "// MPCitH Parameters".to_string(),
        const_declaration!(#[doc = "(t) Number of random evaluation points"] pub(crate) PARAM_T = category.mpc_param_t),
        const_declaration!(#[doc = "(η) F_point size for F_point = F_(q^η)"] pub(crate) PARAM_ETA = category.mpc_param_eta),
        const_declaration!(#[doc = "(N) Number of secret parties = q"] pub(crate) PARAM_N = category.mpc_param_n),
        const_declaration!(#[doc = "(τ) Number of repetitions of the protocol"] pub(crate) PARAM_TAU = category.mpc_param_tau),
        const_declaration!(#[doc = "(ℓ) Privacy threshold (number of open parties)"] pub(crate) PARAM_L = category.mpc_param_l),
        
        "// Signature Parameters".to_string(),
        const_declaration!(#[doc = "Seed size in bytes"] pub PARAM_SEED_SIZE = (category.param_seed_size / 8)),
        const_declaration!(#[doc = "Salt size in bytes"] pub PARAM_SALT_SIZE = (category.param_salt_size / 8)),
        const_declaration!(#[doc = "Digest (Hash) size in bytes"] pub PARAM_DIGEST_SIZE = (category.param_digest_size / 8)),
        
        "// Computed Parameters".to_string(),
        const_declaration!(#[doc = "(log_2(N)) Number of log2(nb_parties) for the number of parties"] pub(crate) PARAM_LOG_N = (category.mpc_param_n.ilog2() as usize)),
        const_declaration!(#[doc = "(λ) Security parameter. E.g. used for the 2λ bit salt for commitments"] pub(crate) PARAM_LAMBDA = (category.sd_param_q / 2)),
        const_declaration!(#[doc = "m - k"] pub(crate) PARAM_M_SUB_K = (category.sd_param_m - category.sd_param_k)),
        const_declaration!(#[doc = "Chunk size for the splitting variant of the Syndrome Decoding Problem for Code Length m"] pub(crate) PARAM_CHUNK_M = (category.sd_param_m / category.sd_param_splitting_factor)),
        const_declaration!(#[doc = "Chunk size for the splitting variant of the Syndrome Decoding Problem for Hamming weight w"] pub(crate) PARAM_CHUNK_W = (category.sd_param_w / category.sd_param_splitting_factor)),

        "// Weird params from spec, TODO remove?".to_string(),
        const_declaration!(#[doc = "m-k rounded up to 32 for performance"] pub(crate) PARAM_M_SUB_K_CEIL32 = (((category.sd_param_m - category.sd_param_k + 31) >> 5) << 5)),
        const_declaration!(#[doc = "m rounded up to 32 for performance"] pub(crate) PARAM_M_CEIL32 = (((category.sd_param_m + 31) >> 5) << 5)),

        "// Primitives".to_string(),
        const_declaration!(#[doc = "Hash primitive used in the signature scheme"] pub HASH_PRIMITIVE = category.primitive_hash),
        const_declaration!(#[doc = "XOF primitive used in the signature scheme"] pub XOF_PRIMITIVE = category.primitive_xof),
    ].join("\n")
}

static CATEGORY_ONE: Category = Category {
    category: Categories::ONE,
    sd_param_q: 256,
    sd_param_m: 242,
    sd_param_k: 126,
    sd_param_w: 87,
    sd_param_splitting_factor: 1,
    mpc_param_n: 256,
    mpc_param_l: 3,
    mpc_param_tau: 6,
    mpc_param_eta: 4,
    mpc_param_t: 7,
    param_seed_size: 128,
    param_salt_size: 256,
    param_digest_size: 256,
    primitive_hash: HashPrimitive::SHA3_256,
    primitive_xof: XOFPrimitive::SHAKE128,
    precomputed: Precomputed {
        precomputed_f_poly: &[
            0, 236, 238, 23, 164, 169, 114, 156, 211, 182, 70, 113, 128, 254, 46, 57, 236, 121,
            249, 249, 101, 129, 184, 110, 158, 168, 119, 107, 167, 171, 122, 175, 35, 209, 242,
            154, 83, 189, 10, 193, 169, 30, 84, 154, 220, 116, 27, 161, 166, 57, 122, 244, 61, 59,
            20, 184, 0, 91, 240, 182, 9, 140, 140, 0, 150, 76, 241, 195, 44, 116, 148, 106, 180,
            31, 205, 48, 197, 46, 231, 74, 208, 236, 208, 152, 159, 36, 254, 155, 199, 63, 77, 126,
            108, 206, 206, 0, 66, 112, 196, 45, 92, 183, 43, 239, 204, 80, 225, 4, 119, 143, 143,
            0, 204, 205, 137, 204, 38, 225, 225, 0, 24, 44, 44, 0, 0, 0, 0, 0, 49, 79, 122, 185,
            125, 43, 139, 116, 197, 114, 250, 112, 118, 65, 54, 68, 96, 118, 86, 225, 185, 245,
            209, 140, 198, 173, 165, 103, 27, 237, 237, 0, 216, 138, 2, 10, 185, 45, 241, 246, 192,
            217, 172, 19, 176, 162, 162, 0, 115, 218, 26, 194, 184, 213, 213, 0, 12, 22, 22, 0, 0,
            0, 0, 0, 69, 192, 114, 103, 0, 73, 198, 62, 21, 44, 38, 48, 152, 11, 11, 0, 167, 100,
            136, 41, 11, 180, 180, 0, 120, 156, 156, 0, 0, 0, 0, 0, 194, 98, 11, 39, 34, 129, 129,
            0, 218, 167, 167, 0, 0, 0, 0, 0, 182, 1, 1,
        ],
        precomputed_leading_coefficients_of_lj_for_s: &[
            93, 93, 214, 214, 169, 169, 228, 228, 45, 45, 171, 171, 22, 22, 33, 33, 56, 56, 108,
            108, 55, 55, 128, 128, 68, 68, 93, 93, 220, 220, 81, 81, 73, 73, 106, 106, 51, 51, 20,
            20, 188, 188, 167, 167, 117, 117, 29, 29, 239, 239, 145, 145, 202, 202, 149, 149, 191,
            191, 185, 185, 113, 113, 33, 33, 65, 65, 160, 160, 177, 177, 14, 14, 50, 50, 114, 114,
            247, 247, 158, 158, 49, 49, 107, 107, 243, 243, 210, 210, 218, 218, 97, 97, 117, 117,
            194, 194, 181, 181, 135, 135, 87, 87, 249, 249, 205, 205, 107, 107, 102, 102, 43, 43,
            215, 215, 220, 220, 163, 163, 17, 17, 158, 158, 65, 65, 251, 251, 234, 234, 117, 117,
            89, 89, 46, 46, 10, 10, 52, 52, 182, 182, 198, 198, 59, 59, 196, 196, 103, 103, 124,
            124, 242, 242, 130, 130, 207, 207, 203, 203, 220, 220, 58, 58, 91, 91, 3, 3, 168, 168,
            242, 242, 8, 8, 30, 30, 89, 89, 147, 147, 255, 255, 237, 237, 110, 110, 245, 245, 66,
            66, 6, 6, 41, 41, 33, 33, 9, 9, 38, 38, 158, 158, 107, 107, 65, 65, 63, 63, 242, 242,
            166, 166, 101, 101, 139, 139, 253, 253, 127, 127, 254, 254, 89, 89, 26, 26, 57, 57, 39,
            39, 192, 192, 140, 140, 116, 116, 93, 93, 162, 162, 174, 174, 119, 119,
        ],
    },
};

static CATEGORY_THREE: Category = Category {
    category: Categories::THREE,
    sd_param_q: 256,
    sd_param_m: 376,
    sd_param_k: 220,
    sd_param_w: 114,
    sd_param_splitting_factor: 2,
    mpc_param_n: 256,
    mpc_param_l: 3,
    mpc_param_tau: 9,
    mpc_param_eta: 4,
    mpc_param_t: 10,
    param_seed_size: 192,
    param_salt_size: 384,
    param_digest_size: 384,
    primitive_hash: HashPrimitive::SHA3_384,
    primitive_xof: XOFPrimitive::SHAKE256,
    precomputed: Precomputed {
        precomputed_f_poly: &[
            0, 197, 158, 11, 89, 79, 116, 248, 234, 125, 162, 193, 110, 120, 135, 229, 145, 67, 35,
            245, 81, 162, 173, 168, 224, 59, 59, 88, 228, 149, 153, 152, 199, 118, 86, 103, 109,
            15, 20, 99, 240, 223, 208, 50, 30, 184, 219, 64, 126, 171, 197, 89, 248, 188, 87, 233,
            208, 45, 134, 215, 80, 253, 7, 0, 244, 125, 83, 51, 48, 163, 12, 166, 123, 245, 18,
            219, 35, 210, 180, 26, 205, 187, 165, 152, 240, 24, 215, 214, 180, 51, 206, 144, 82,
            188, 71, 0, 238, 34, 219, 185, 22, 28, 78, 204, 19, 12, 108, 138, 213, 166, 93, 0, 31,
            73, 128, 70, 176, 106, 145, 0, 196, 44, 215, 0, 251, 0, 0, 0, 84, 250, 47, 99, 121,
            253, 199, 185, 47, 213, 252, 91, 222, 63, 204, 194, 211, 138, 67, 151, 119, 21, 199,
            167, 154, 97, 193, 223, 108, 217, 216, 0, 249, 156, 198, 207, 3, 47, 15, 101, 21, 193,
            147, 29, 92, 27, 26, 0, 212, 66, 49, 120, 24, 126, 127, 0, 18, 6, 7, 0, 1,
        ],
        precomputed_leading_coefficients_of_lj_for_s: &[
            212, 212, 212, 212, 149, 149, 149, 149, 53, 53, 53, 53, 116, 116, 116, 116, 27, 27, 27,
            27, 90, 90, 90, 90, 250, 250, 250, 250, 187, 187, 187, 187, 193, 193, 193, 193, 128,
            128, 128, 128, 32, 32, 32, 32, 97, 97, 97, 97, 14, 14, 14, 14, 79, 79, 79, 79, 239,
            239, 239, 239, 174, 174, 174, 174, 101, 101, 101, 101, 17, 17, 17, 17, 71, 71, 71, 71,
            51, 51, 51, 51, 52, 52, 52, 52, 64, 64, 64, 64, 22, 22, 22, 22, 98, 98, 98, 98, 136,
            136, 136, 136, 252, 252, 252, 252, 170, 170, 170, 170, 222, 222, 222, 222, 217, 217,
            217, 217, 173, 173, 173, 173, 251, 251, 251, 251, 143, 143, 143, 143, 144, 144, 144,
            144, 165, 165, 165, 165, 83, 83, 83, 83, 102, 102, 102, 102, 14, 14, 14, 14, 59, 59,
            59, 59, 205, 205, 205, 205, 248, 248, 248, 248, 104, 104, 104, 104, 93, 93, 93, 93,
            171, 171, 171, 171, 158, 158, 158, 158, 246, 246, 246, 246, 195, 195, 195, 195, 53, 53,
            53, 53,
        ],
    },
};

static CATEGORY_FIVE: Category = Category {
    category: Categories::FIVE,
    sd_param_q: 256,
    sd_param_m: 494,
    sd_param_k: 282,
    sd_param_w: 156,
    sd_param_splitting_factor: 2,
    mpc_param_n: 256,
    mpc_param_l: 3,
    mpc_param_tau: 12,
    mpc_param_eta: 4,
    mpc_param_t: 13,
    param_seed_size: 256,
    param_salt_size: 512,
    param_digest_size: 512,
    primitive_hash: HashPrimitive::SHA3_512,
    primitive_xof: XOFPrimitive::SHAKE256,
    precomputed: Precomputed {
        precomputed_f_poly: &[
            0, 104, 237, 143, 128, 173, 133, 213, 151, 17, 45, 104, 111, 186, 186, 243, 66, 29, 25,
            37, 46, 236, 151, 23, 15, 217, 240, 136, 77, 99, 95, 39, 54, 170, 191, 22, 78, 251, 64,
            40, 150, 7, 115, 60, 123, 171, 90, 103, 83, 205, 112, 54, 209, 166, 245, 64, 157, 8,
            46, 194, 137, 225, 206, 169, 114, 223, 110, 136, 75, 239, 93, 197, 84, 242, 143, 156,
            162, 127, 27, 142, 164, 137, 146, 9, 53, 162, 145, 243, 89, 90, 151, 129, 173, 145, 11,
            131, 69, 244, 150, 221, 72, 218, 247, 183, 122, 202, 171, 210, 187, 143, 179, 103, 21,
            148, 168, 121, 222, 5, 232, 156, 149, 199, 179, 103, 90, 119, 193, 44, 75, 132, 108,
            32, 78, 36, 19, 58, 116, 177, 234, 252, 84, 126, 142, 22, 93, 118, 233, 107, 12, 150,
            169, 79, 90, 36, 146, 42, 99, 67, 184, 228, 47, 169, 231, 239, 150, 196, 37, 94, 107,
            9, 128, 138, 94, 36, 2, 3, 168, 252, 190, 221, 244, 217, 202, 175, 104, 147, 228, 150,
            45, 182, 237, 22, 61, 111, 117, 2, 13, 52, 46, 61, 191, 229, 166, 145, 211, 33, 0, 0,
            168, 190, 146, 41, 111, 33, 38, 53, 162, 81, 225, 28, 41, 176, 232, 156, 241, 110, 247,
            147, 70, 131, 109, 214, 76, 186, 42, 63, 60, 34, 51, 167, 135, 237, 107, 211, 98, 83,
            247, 1,
        ],
        precomputed_leading_coefficients_of_lj_for_s: &[
            244, 122, 243, 125, 250, 116, 253, 115, 61, 199, 210, 40, 248, 2, 23, 237, 20, 168,
            119, 203, 210, 110, 177, 13, 87, 159, 220, 20, 90, 146, 209, 25, 241, 254, 239, 224,
            205, 194, 211, 220, 94, 37, 168, 211, 169, 210, 95, 36, 195, 254, 185, 132, 55, 10, 77,
            112, 230, 175, 116, 61, 217, 144, 75, 2, 143, 216, 33, 118, 200, 159, 102, 49, 208,
            243, 150, 181, 92, 127, 26, 57, 100, 1, 174, 203, 235, 142, 33, 68, 177, 160, 147, 130,
            245, 228, 215, 198, 249, 47, 78, 152, 140, 90, 59, 237, 192, 98, 159, 61, 126, 220, 33,
            131, 192, 36, 19, 247, 125, 153, 174, 74, 115, 227, 72, 216, 5, 149, 62, 174, 141, 147,
            177, 175, 245, 235, 201, 215, 160, 202, 116, 30, 19, 121, 199, 173, 198, 234, 158, 178,
            118, 90, 46, 2, 97, 57, 209, 137, 26, 66, 170, 242, 15, 144, 42, 181, 69, 218, 96, 255,
            68, 175, 137, 98, 197, 46, 8, 227, 150, 59, 215, 122, 20, 185, 85, 248, 87, 142, 254,
            39, 30, 199, 183, 110, 52, 243, 161, 102, 5, 194, 144, 87, 143, 60, 242, 65, 117, 198,
            8, 187, 116, 129, 133, 112, 141, 120, 124, 137, 69, 196, 92, 221, 119, 246, 110, 239,
            197, 131, 73, 15, 198, 128, 74, 12, 24, 42, 124, 78, 208, 226, 180, 134, 87, 35, 191,
            203, 156, 232, 116,
        ],
    },
};

#[derive(CompileConst, Clone, Copy, Debug, PartialEq)]
#[inherit_docs]
/// Compiled version category of the protocol
enum Categories {
    ONE = 1,
    THREE = 3,
    FIVE = 5,
}

impl From<String> for Categories {
    fn from(s: String) -> Self {
        match s.as_str() {
            "1" => Categories::ONE,
            "ONE" => Categories::ONE,
            "3" => Categories::THREE,
            "THREE" => Categories::THREE,
            "5" => Categories::FIVE,
            "FIVE" => Categories::FIVE,
            _ => panic!("Invalid category"),
        }
    }
}

#[derive(CompileConst, Clone, Copy, Debug)]
#[inherit_docs]
/// Hash primitive used in the signature scheme
enum HashPrimitive {
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

#[derive(CompileConst, Clone, Copy, Debug)]
#[inherit_docs]
/// XOF primitive used in the signature scheme
enum XOFPrimitive {
    SHAKE128,
    SHAKE256,
}

#[derive(Debug, Clone, Copy)]
struct Category {
    category: Categories,
    // SD Parameters
    sd_param_q: usize,
    sd_param_m: usize,
    sd_param_k: usize,
    sd_param_w: usize,
    sd_param_splitting_factor: usize,

    // MPCitH Parameters
    mpc_param_n: usize,
    mpc_param_l: usize,
    mpc_param_tau: usize,
    mpc_param_eta: usize,
    mpc_param_t: usize,

    // Signature Parameters
    param_seed_size: usize,
    param_salt_size: usize,
    param_digest_size: usize,

    // Primitives
    primitive_hash: HashPrimitive,
    primitive_xof: XOFPrimitive,

    // Computed Parameters
    precomputed: Precomputed<'static>,
}

#[derive(Clone, Copy, Debug)]
/// Precomputed values F is PARAM_CHUNK_M + 1 and S is PARAM_CHUNK_M
struct Precomputed<'a> {
    precomputed_f_poly: &'a [u8],
    precomputed_leading_coefficients_of_lj_for_s: &'a [u8],
}

impl Precomputed<'_> {
    fn output(&self) -> String {
        vec![
            format!("#[doc = \"Precomputed public polynomial F\"] pub(crate) const PRECOMPUTED_F_POLY: [u8; {}] = {:?};", self.precomputed_f_poly.len(), self.precomputed_f_poly),
            format!("#[doc = \"Lagrange coefficients for computing S\"] pub(crate) const PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S: [u8; {}] = {:?};", self.precomputed_leading_coefficients_of_lj_for_s.len(), self.precomputed_leading_coefficients_of_lj_for_s),
        ].join("\n")
    }
}
