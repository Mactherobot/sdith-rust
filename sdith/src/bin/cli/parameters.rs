use clap::{Error, Parser};
use colored::Colorize as _;

use rsdith::constants::params::{self};

#[derive(Parser)]
#[command(version, about("SDitH signature protocol -- print parameters"), long_about = None)]
pub struct Parameters {}

impl Parameters {
    pub fn print_info(&self) -> Result<(), Error> {
        println!("SDitH signature protocol parameters");

        if cfg!(feature = "category_three") {
            println!("NIST Category THREE variant");
        } else if cfg!(feature = "category_five") {
            println!("NIST Category FIVE variant");
        } else {
            println!("NIST Category ONE variant");
        }

        println!();

        println!("{}", "SD Parameters:".blue().bold());
        println!(
            "{}\t(q) The Galois field size GL(q) = GL(2^8) = GL(256)",
            params::PARAM_Q.to_string().bold()
        );
        println!("{}\t(M) Code length", params::PARAM_M.to_string().bold());
        println!(
            "{}\t(K) Vector dimension",
            params::PARAM_K.to_string().bold()
        );
        println!(
            "{}\t(w) The Hamming weight bound PARAM_CODE_WEIGHT",
            params::PARAM_W.to_string().bold()
        );
        println!(
            "{}\t(d) Splitting factor for the syndrome variant",
            params::PARAM_SPLITTING_FACTOR.to_string().bold()
        );

        println!("{}", "MPCitH Parameters:".blue().bold());
        println!(
            "{}\t(t) Number of random evaluation points",
            params::PARAM_T.to_string().bold()
        );
        println!(
            "{}\t(η) F_point size for F_point = F_(q^η)",
            params::PARAM_ETA.to_string().bold()
        );
        println!(
            "{}\t(N) Number of secret parties = q",
            params::PARAM_N.to_string().bold()
        );
        println!(
            "{}\t(τ) Number of repetitions of the protocol",
            params::PARAM_TAU.to_string().bold()
        );
        println!(
            "{}\t(ℓ) Privacy threshold (number of open parties)",
            params::PARAM_L.to_string().bold()
        );

        println!("{}", "\nSignature Parameters:".blue().bold());
        println!(
            "{}\tSeed size in bytes",
            params::PARAM_SEED_SIZE.to_string().bold()
        );
        println!(
            "{}\tSalt size in bytes",
            params::PARAM_SALT_SIZE.to_string().bold()
        );
        println!(
            "{}\tDigest (Hash) size in bytes",
            params::PARAM_DIGEST_SIZE.to_string().bold()
        );

        return Ok(());
    }
}
