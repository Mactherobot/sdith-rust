//! Keygen

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Error, Parser};
use colored::Colorize as _;

use rsdith::{
    keygen::{self, PublicKey, SecretKey},
    utils::marshalling::Marshalling as _,
};

use crate::utilities::{get_seed, print_title};

#[derive(Parser)]
#[command(version, about("SDitH signature protocol -- key generation"), long_about = None)]
pub struct Keygen {
    /// Master seed. Must be 32 bytes long.
    #[arg(short, long)]
    seed: Option<String>,

    /// Output files
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output public key (default: true)
    #[arg(long("pk"), action=ArgAction::SetTrue, conflicts_with("sec_key"))]
    pub_key: bool,

    /// Output secret key (default: true)
    #[arg(long("sk"), action=ArgAction::SetTrue, conflicts_with("pub_key"))]
    sec_key: bool,
}

impl Keygen {
    /// Output keys to file or stdout. Returns true if keys are saved to file. False if printed to stdout.
    fn output_keys(&self, pk: PublicKey, sk: SecretKey) -> Result<bool, Error> {
        // If no output file is provided, print to stdout
        let print_all = !self.pub_key && !self.sec_key;
        if self.output.is_none() {
            if print_all || self.pub_key {
                eprint!("\n{}", "Public key: ".blue());
                println!("{}", STANDARD.encode(pk.serialise()));
            }

            if print_all || self.sec_key {
                eprint!("\n{}", "Secret key: ".blue());
                println!("{}", STANDARD.encode(sk.serialise()));
            }

            return Ok(false);
        }

        let path_arg = self.output.as_ref().unwrap();
        let mut path_buf = path_arg.clone();

        let path = if path_buf.is_dir() {
            path_buf.push("sdith");
            Path::new(&path_buf)
        } else {
            Path::new(&path_buf)
        };

        // Save public key to output file
        if print_all || self.pub_key {
            let pk_path = path.with_extension("pub");
            std::fs::File::create(&pk_path)?;
            std::fs::write(&pk_path, STANDARD.encode(pk.serialise()))?;
            eprintln!("{} {:?}", "Public key saved to".blue(), pk_path.display());
        }

        // Save secret key to output file
        if print_all || self.sec_key {
            let sk_path = path.with_extension("");
            std::fs::File::create(&sk_path)?;
            std::fs::write(&sk_path, STANDARD.encode(sk.serialise()))?;
            eprintln!("{} {:?}", "Secret key saved to".blue(), sk_path.display());
        }

        return Ok(true);
    }

    pub fn generate_keys(&self) -> Result<(), Error> {
        print_title("Generating SDitH key pair.");
        let seed = get_seed(self.seed.as_ref())?;

        let (pk, sk) = keygen::keygen(seed);

        self.output_keys(*pk, *sk)?;

        Ok(())
    }
}
