pub(crate) mod input;
mod sign;
pub(crate) mod signature;
mod verify;

#[cfg(test)]
mod signing_and_verifying_tests {
    use super::signature::Signature;
    use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_sign_verify_signature() {
        let seed_root = [0u8; PARAM_SEED_SIZE];
        let (pk, sk) = crate::keygen::keygen(seed_root);
        let message = b"Hello, World!";
        let entropy = (seed_root, [0u8; PARAM_SALT_SIZE]);

        let signature = Signature::sign_message(entropy, sk, message);
        let valid = Signature::verify_signature(pk, signature, message);

        if valid.is_err() {
            println!("{:?}", valid);
        }
        assert!(valid.is_ok());
    }
}
