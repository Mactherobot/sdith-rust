//! Signing

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::Path;

use clap::{Error, Parser};

use rsdith::{keygen::SecretKey, signature::Signature, utils::marshalling::Marshalling as _};

use crate::utilities::{
    clap_err_result, clap_err_result_msg, get_decoded_string_from_file_or_string, get_salt,
    get_seed, print_title,
};

#[derive(Parser)]
#[command(version, about("SDitH signature protocol -- signing"), long_about = None)]
pub struct Signing {
    /// Message file or string
    #[arg(short, long)]
    pub msg: String,

    /// Secret key file or string
    #[arg(long("sk"))]
    pub secret_key: String,

    /// Signing seed
    #[arg(long)]
    pub seed: Option<String>,

    /// Signing salt
    #[arg(long)]
    pub salt: Option<String>,
}

impl Signing {
    fn get_secret_key(&self) -> Result<SecretKey, Error> {
        let decoded_secret_key = get_decoded_string_from_file_or_string(
            self.secret_key.clone(),
            Some("Secret Key".to_string()),
        )?;
        clap_err_result_msg!(
            SecretKey::parse(&decoded_secret_key),
            "Could not parse secret key"
        )
    }

    fn get_msg(&self) -> Result<Vec<u8>, Error> {
        let path = Path::new(&self.msg);
        if path.exists() {
            clap_err_result_msg!(
                STANDARD.decode(std::fs::read_to_string(path)?.trim()),
                "Could not decode message using base64"
            )
        } else {
            Ok(self.msg.clone().into_bytes())
        }
    }

    pub fn sign_message(&self) -> Result<(), Error> {
        print_title("Signing message.");
        let secret_key = self.get_secret_key()?;
        let msg = self.get_msg()?;
        let seed = get_seed(self.seed.as_ref())?;
        let salt = get_salt(self.salt.as_ref())?;
        let signature = clap_err_result!(Signature::sign_message((seed, salt), &secret_key, &msg))?;

        eprintln!("");
        println!("{}", STANDARD.encode(signature.serialise()));
        Ok(())
    }
}
