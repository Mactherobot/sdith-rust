mod spec_constants;
mod spec_keygen;
mod spec_utils;
mod spec_witness;
mod spec_xof;

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

/// Read the files generated by the specification library, PQCsignKAT_404.req and PQCsignKAT_404.rsp
fn read_response_test_vectors(n: usize) -> Vec<TestVectorResponse> {
    let rsp_file = include_str!("PQCsignKAT_432.rsp");
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
mod spec_tests {
    use super::*;

    use crate::{
        arith::arrays::Array3DTrait,
        constants::params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_TAU},
        keygen::keygen,
        mpc::broadcast::{BROADCAST_PLAIN_SIZE, BROADCAST_SHARE_PLAIN_SIZE},
        signature::signature::Signature,
        subroutines::marshalling::Marshalling as _,
        witness::SOLUTION_PLAIN_SIZE,
    };

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
    fn test_keygen_compare_spec() {
        let v = read_response_test_vectors(100);
        for tv in v {
            let (pk, sk) = keygen(tv.nist_entropy.keygen_seed);
            assert_eq!(pk.serialise(), tv.pk.serialise());
            assert_eq!(sk.serialise(), tv.sk.serialise());
        }
    }

    #[test]
    fn test_signature_generation_compare_spec() {
        // Read all test vectors.
        let test_vectors = read_response_test_vectors(10); // TODO: test all 100 vectors

        for (vi, tv) in test_vectors.iter().enumerate() {
            let signature_plain = Signature::sign_message(
                (tv.nist_entropy.sign_seed, tv.nist_entropy.sign_salt),
                tv.sk,
                &tv.msg,
            )
            .unwrap();
            let spec_signature_parsed = Signature::parse(&tv.sm).unwrap();
            let sign = Signature::parse(&signature_plain).unwrap();

            // Test the signature parts
            assert_eq!(
                sign.message, spec_signature_parsed.message,
                "Message mismatch ({})",
                vi
            );
            assert_eq!(
                sign.salt, spec_signature_parsed.salt,
                "Salt mismatch ({})",
                vi
            );
            assert_eq!(sign.h1, spec_signature_parsed.h1, "H1 mismatch ({})", vi);
            assert_eq!(
                sign.broadcast_plain, spec_signature_parsed.broadcast_plain,
                "Broadcast plain mismatch ({})",
                vi
            );

            for e in 0..PARAM_TAU {
                for i in 0..PARAM_L {
                    assert_eq!(
                        sign.broadcast_shares.get_row_slice(e, i),
                        spec_signature_parsed.broadcast_shares.get_row_slice(e, i),
                        "Broadcast shares mismatch e: {}, i: {} ({})",
                        e,
                        i,
                        vi
                    );
                    assert_eq!(
                        sign.solution_share.get_row_slice(e, i),
                        spec_signature_parsed.solution_share.get_row_slice(e, i),
                        "Solution shares mismatch e: {}, i: {} ({})",
                        e,
                        i,
                        vi
                    );
                }
            }
            for e in 0..PARAM_TAU {
                for j in 0..sign.auth[e].len() {
                    assert_eq!(
                        sign.auth[e][j], spec_signature_parsed.auth[e][j],
                        "Auth mismatch ({}) for e: {}, j: {}",
                        vi, e, j
                    );
                }
            }
        }
    }

    #[test]
    fn test_parse_serialise_signature_from_spec() {
        let test_vectors = read_response_test_vectors(100); // TODO: test all 100 vectors

        for (i, tv) in test_vectors.iter().enumerate() {
            let parsed_signature = Signature::parse(&tv.sm).unwrap();
            // Testing the length of the signature
            assert_eq!(tv.smlen, tv.sm.len());
            assert_eq!((tv.smlen - tv.mlen - 4).to_le_bytes()[..4], tv.sm[..4]);

            let mut offset = 4;
            // Test message
            assert_eq!(parsed_signature.message, tv.msg);
            assert_eq!(
                parsed_signature.message,
                tv.sm[offset..offset + tv.mlen].to_vec()
            );
            offset += tv.mlen;

            // Test salt
            assert_eq!(parsed_signature.salt, tv.nist_entropy.sign_salt);
            assert_eq!(
                parsed_signature.salt,
                tv.sm[offset..offset + PARAM_SALT_SIZE]
            );
            offset += PARAM_SALT_SIZE;

            // Test h1
            assert_eq!(
                parsed_signature.h1,
                tv.sm[offset..offset + PARAM_DIGEST_SIZE]
            );
            offset += PARAM_DIGEST_SIZE;

            // Test broadcast_plain
            assert_eq!(
                parsed_signature.broadcast_plain,
                tv.sm[offset..offset + BROADCAST_PLAIN_SIZE]
            );
            offset += BROADCAST_PLAIN_SIZE;

            // Test broadcast_shares and solution_shares
            for e in 0..PARAM_TAU {
                for i in 0..PARAM_L {
                    assert_eq!(
                        *parsed_signature.broadcast_shares.get_row_slice(e, i),
                        tv.sm[offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
                    );
                    offset += BROADCAST_SHARE_PLAIN_SIZE;
                    assert_eq!(
                        *parsed_signature.solution_share.get_row_slice(e, i),
                        tv.sm[offset..offset + SOLUTION_PLAIN_SIZE]
                    );
                    offset += SOLUTION_PLAIN_SIZE;
                }
            }

            // Test auth
            for e in 0..PARAM_TAU {
                for j in 0..parsed_signature.auth[e].len() {
                    assert_eq!(
                        parsed_signature.auth[e][j],
                        tv.sm[offset..offset + PARAM_DIGEST_SIZE]
                    );
                    offset += PARAM_DIGEST_SIZE;
                }
            }

            assert_eq!(offset, tv.sm.len(), "Rest?: {:?}", &tv.sm[offset..]);

            // Test re-serialisation
            assert_eq!(
                parsed_signature.serialise(),
                tv.sm,
                "Incorrect serialisation of signature"
            );
        }
    }

    #[test]
    fn test_verification_with_spec_signature() {
        let test_vectors = read_response_test_vectors(100); // TODO: test all 100 vectors
        for tv in test_vectors {
            let verification = Signature::verify_signature(tv.pk, &tv.sm);
            assert!(verification.is_ok(), "Signature verification failed: {:?}", verification);
            assert!(verification.unwrap(), "Signature verification failed");
        }
    }
}
