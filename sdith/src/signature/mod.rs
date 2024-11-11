pub mod input;
mod sign;
pub mod signature;
mod verify;

#[cfg(test)]
mod signing_and_verifying_tests {

    use super::signature::Signature;
    use crate::{
        constants::{
            params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
            types::Seed,
        },
        keygen::keygen,
    };

    #[test]
    fn test_sign_verify_signature() {
        let spec_master_seed: Seed = [0u8; PARAM_SEED_SIZE];
        let (pk, sk) = keygen(spec_master_seed);
        let message = b"Hello, World!".to_vec();
        let entropy = (spec_master_seed, [0u8; PARAM_SALT_SIZE]);

        let signature = Signature::sign_message(entropy, &sk, &message).unwrap();
        let valid = Signature::verify_signature(&pk, &signature);

        if valid.is_err() {
            println!("{:?}", valid);
        }
        assert!(valid.is_ok());
    }
}
