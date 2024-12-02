mod utils;

use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, RngCore, SeedableRng};

use crate::{
    constants::{
        params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        types::{Salt, Seed},
    },
    keygen::{PublicKey, SecretKey},
};

pub(self) const SPEC_MASTER_SEED: Seed = [
    124, 153, 53, 160, 176, 118, 148, 170, 12, 109, 16, 228, 219, 107, 26, 221,
];

struct NistEntropy {
    keygen_seed: Seed,
    sign_salt: Salt,
    sign_seed: Seed,
}

impl NistEntropy {
    fn new(seed: nist_pqc_seeded_rng::Seed) -> Self {
        // Initiate NIST rng
        let mut rng = NistPqcAes256CtrRng::from_seed(seed);
        let mut keygen_seed: Seed = [0u8; PARAM_SEED_SIZE];

        // First create master seed
        rng.fill_bytes(&mut keygen_seed);

        // Next create salt
        let mut sign_salt: Salt = [0u8; PARAM_SALT_SIZE];
        rng.fill_bytes(&mut sign_salt);

        // Finally create signing seed
        let mut sign_seed: Seed = [0u8; PARAM_SEED_SIZE];
        rng.fill_bytes(&mut sign_seed);

        NistEntropy {
            keygen_seed,
            sign_salt,
            sign_seed,
        }
    }
}

struct TestVectorResponse {
    count: usize,
    nist_entropy: NistEntropy,
    mlen: usize,
    msg: Vec<u8>,
    pk: PublicKey,
    sk: SecretKey,
    sm: Vec<u8>,
    smlen: usize,
}

fn seed_from_hex(hex: &str) -> nist_pqc_seeded_rng::Seed {
    hex::decode(hex).unwrap()[..48].try_into().unwrap()
}

fn get_value_from_line(line: &str) -> &str {
    line.split(" = ").collect::<Vec<&str>>()[1]
}

fn get_response_file() -> &'static str {
    if cfg!(feature = "category_one") {
        println!("category_one");
        include_str!("./vectors/cat1_gf256/PQCsignKAT.rsp")
    } else if cfg!(feature = "category_three") {
        println!("category_three");
        include_str!("./vectors/cat3_gf256/PQCsignKAT.rsp")
    } else if cfg!(feature = "category_five") {
        println!("category_five");
        include_str!("./vectors/cat5_gf256/PQCsignKAT.rsp")
    } else {
        panic!("No category feature enabled")
    }
}

/// Read the files generated by the specification library, PQCsignKAT_404.req and PQCsignKAT_404.rsp
fn read_response_test_vectors(n: usize) -> Vec<TestVectorResponse> {
    let rsp_file = get_response_file();
    let mut rsp_lines = rsp_file.lines();
    rsp_lines.next(); // Skip the first line -> # sdith_threshold_cat1_gf256

    let mut test_vectors = Vec::new();
    let mut read_vectors = 0;

    while read_vectors < n {
        rsp_lines.next(); // Skip empty line
        let count: usize = get_value_from_line(rsp_lines.next().unwrap())
            .parse()
            .unwrap();
        let seed = seed_from_hex(&get_value_from_line(rsp_lines.next().unwrap()));
        let mlen: usize = get_value_from_line(rsp_lines.next().unwrap())
            .parse()
            .unwrap();

        let msg = hex::decode(get_value_from_line(rsp_lines.next().unwrap())).unwrap();
        let pk = PublicKey::parse_from_hex(&get_value_from_line(rsp_lines.next().unwrap()));
        let sk = SecretKey::parse_from_hex(&get_value_from_line(rsp_lines.next().unwrap()));
        let smlen: usize = get_value_from_line(rsp_lines.next().unwrap())
            .parse()
            .unwrap();
        let sm = hex::decode(get_value_from_line(rsp_lines.next().unwrap())).unwrap();

        test_vectors.push(TestVectorResponse {
            count,
            nist_entropy: NistEntropy::new(seed),
            mlen,
            msg,
            pk,
            sk,
            sm,
            smlen,
        });
        read_vectors += 1;
    }

    test_vectors
}

#[cfg(test)]
mod kat_tests {
    use super::*;

    use crate::{keygen::keygen, signature::Signature, subroutines::marshalling::Marshalling};

    #[test]
    fn test_read_test_vectors() {
        let v = read_response_test_vectors(2);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].nist_entropy.keygen_seed, SPEC_MASTER_SEED);
        assert!(v[0].count == 0);
        assert!(v[0].mlen == 33);
        assert_eq!(
            hex::encode(&v[0].msg).to_uppercase(),
            "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8"
        );
        assert!(v[0].smlen == 10301);
    }

    #[test]
    fn test_signing_and_verifying() {
        let v = read_response_test_vectors(100);
        for tv in v {
            let (pk, sk) = keygen(tv.nist_entropy.keygen_seed);
            let signature = Signature::sign_message(
                (tv.nist_entropy.sign_seed, tv.nist_entropy.sign_salt),
                &sk,
                &tv.msg,
            );
            assert!(signature.is_ok());
            let signature = signature.unwrap();

            let verification = Signature::verify_signature(&pk, &signature.serialise());
            assert!(verification.is_ok());
        }
    }
}
