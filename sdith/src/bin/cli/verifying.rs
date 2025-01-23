//! Verification

use clap::{Error, Parser};
use colored::Colorize as _;
use rsdith::keygen::PublicKey;

use rsdith::{signature::Signature, utils::marshalling::Marshalling as _};

use crate::utilities::{clap_err_result_msg, get_decoded_string_from_file_or_string, print_title};

#[derive(Parser)]
#[command(version, about("SDitH signature protocol -- verification"), long_about = None)]
pub struct Verifying {
    /// Public key file or string
    #[arg(long("pk"))]
    pub pub_key: String,

    /// Signature file or string
    #[arg(short, long)]
    pub signature: String,
}

impl Verifying {
    fn get_public_key(&self) -> Result<PublicKey, Error> {
        let decoded_public_key = get_decoded_string_from_file_or_string(
            self.pub_key.clone(),
            Some("Public Key".to_string()),
        )?;
        clap_err_result_msg!(
            PublicKey::parse(&decoded_public_key),
            "Could not parse public key"
        )
    }

    pub fn verify_signature(&self) -> Result<(), Error> {
        print_title("Verifying message.");
        let pk = self.get_public_key()?;
        let signature = get_decoded_string_from_file_or_string(
            self.signature.clone(),
            Some("Signature".to_string()),
        )?;

        let is_valid = match Signature::verify_signature(&pk, &signature) {
            Ok(is_valid) => is_valid,
            Err(_) => false,
        };

        eprint!(
            "{}",
            match is_valid {
                true => "Signature is valid: ".green(),
                false => "Signature is invalid: ".red(),
            }
        );

        println!("{}", is_valid);

        Ok(())
    }
}
