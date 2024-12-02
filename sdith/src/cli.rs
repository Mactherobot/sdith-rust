use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Error, Parser, Subcommand};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use sdith::{
    constants::{
        params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        types::{Salt, Seed},
    },
    keygen::{self, PublicKey, SecretKey},
    signature::Signature,
    subroutines::marshalling::Marshalling as _,
};

macro_rules! clap_err_result {
    ($e:expr, $t:expr) => {
        match $e {
            Ok(val) => Ok::<_, Error>(val),
            Err(e) => return Err(Error::raw($t, e)),
        }
    };

    ($e:expr) => {
        match $e {
            Ok(val) => Ok::<_, Error>(val),
            Err(e) => return Err(Error::raw(clap::error::ErrorKind::InvalidValue, e)),
        }
    };
}

macro_rules! clap_err_result_msg {
    ($e:expr, $m:expr, $t:expr) => {
        match $e {
            Ok(val) => Ok::<_, Error>(val),
            Err(e) => return Err(Error::raw($t, format!("{}: {}", $m, e))),
        }
    };

    ($e:expr,  $m:expr) => {
        clap_err_result_msg!($e, $m, clap::error::ErrorKind::InvalidValue)
    };
}

#[derive(Parser)]
#[command(version, about("SDitH signature protocol"), long_about = None)]
pub struct Cli {
    // TODO: Implement Category of the protocol. Either 1, 2 or 3.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Keygen(Keygen),
    Sign(Signing),
    Verify(Verifying),
}

#[derive(Parser)]
#[command(version, about("SDitH signature protocol key generation"), long_about = None)]
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
                eprintln!();
                println!("{}", STANDARD.encode(pk.serialise()));
            }

            if print_all || self.sec_key {
                eprintln!();
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
            eprintln!("Public key saved to {:?}", pk_path.display());
        }

        // Save secret key to output file
        if print_all || self.sec_key {
            let sk_path = path.with_extension("");
            std::fs::File::create(&sk_path)?;
            std::fs::write(&sk_path, STANDARD.encode(sk.serialise()))?;
            eprintln!("Secret key saved to {:?}", sk_path.display());
        }

        return Ok(true);
    }

    pub fn generate_keys(&self) -> Result<(), Error> {
        eprintln!("Generating SDitH key pair.");
        let (is_random_seed, seed) = get_seed(self.seed.as_ref())?;
        if is_random_seed {
            eprintln!("Seed: {}", STANDARD.encode(seed));
        }

        let (pk, sk) = keygen::keygen(seed);

        self.output_keys(*pk, *sk)?;

        Ok(())
    }
}

#[derive(Parser)]
#[command(version, about("SDitH signature protocol signing"), long_about = None)]
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
        let decoded_secret_key = get_decoded_string_from_file_or_string(self.secret_key.clone())?;
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
        eprintln!("Signing message.");
        let secret_key = self.get_secret_key()?;
        let msg = self.get_msg()?;
        let (is_random_seed, seed) = get_seed(self.seed.as_ref())?;
        if is_random_seed {
            eprintln!("Seed: {}", STANDARD.encode(seed));
        }
        let (is_random_salt, salt) = get_salt(self.salt.as_ref())?;
        if is_random_salt {
            eprintln!("Salt: {}", STANDARD.encode(salt));
        }
        let signature = clap_err_result!(Signature::sign_message((seed, salt), &secret_key, &msg))?;

        println!("{}", STANDARD.encode(signature.serialise()));
        Ok(())
    }
}

#[derive(Parser)]
#[command(version, about("SDitH signature protocol verification"), long_about = None)]
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
        let decoded_public_key = get_decoded_string_from_file_or_string(self.pub_key.clone())?;
        clap_err_result_msg!(
            PublicKey::parse(&decoded_public_key),
            "Could not parse public key"
        )
    }

    pub fn verify_signature(&self) -> Result<(), Error> {
        eprintln!("Verifying message.");
        let pk = self.get_public_key()?;
        let signature = get_decoded_string_from_file_or_string(self.signature.clone())?;

        let is_valid = match Signature::verify_signature(&pk, &signature) {
            Ok(is_valid) => is_valid,
            Err(_) => false,
        };

        println!("{}", is_valid);

        Ok(())
    }
}

// Utility functions

/// Returns a seed. If no seed is provided, a random seed is generated. Returns true if seed is random.
fn get_seed(_seed: Option<&String>) -> Result<(bool, Seed), Error> {
    let seed = if _seed.is_none() {
        // Generate a random seed using StdRng
        let mut rng = StdRng::from_entropy();
        let mut seed: Seed = [0u8; PARAM_SEED_SIZE];
        rng.fill_bytes(&mut seed);
        seed
    } else {
        let seed_string = _seed.as_ref().unwrap();

        let seed_vec = clap_err_result!(STANDARD.decode(seed_string))?;

        if seed_vec.len() != PARAM_SEED_SIZE {
            return Err(Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("Seed must be {} bytes long", PARAM_SEED_SIZE),
            ));
        }

        let mut seed: Seed = [0u8; PARAM_SEED_SIZE];
        seed.copy_from_slice(&seed_vec);
        seed
    };

    Ok((_seed.is_none(), seed))
}

fn get_salt(_salt: Option<&String>) -> Result<(bool, Salt), Error> {
    let salt = if _salt.is_none() {
        // Generate a random salt using StdRng
        let mut rng = StdRng::from_entropy();
        let mut salt: Salt = [0u8; PARAM_SALT_SIZE];
        rng.fill_bytes(&mut salt);
        salt
    } else {
        let salt_string = _salt.as_ref().unwrap();

        let salt_vec = clap_err_result_msg!(
            STANDARD.decode(salt_string),
            "Could not decode salt from base64"
        )?;

        if salt_vec.len() != PARAM_SALT_SIZE {
            return Err(Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("Salt must be {} bytes long", PARAM_SALT_SIZE),
            ));
        }

        let mut salt: Salt = [0u8; PARAM_SALT_SIZE];
        salt.copy_from_slice(&salt_vec);
        salt
    };

    Ok((_salt.is_none(), salt))
}

/// Checks if the input is a file or a string. Returns the decoded string from the file or the input string.
fn get_decoded_string_from_file_or_string(file_or_string: String) -> Result<Vec<u8>, Error> {
    let path = Path::new(&file_or_string);
    let encoded = if path.exists() {
        eprintln!("Reading from file: {}", path.display());
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        file_or_string.clone()
    };

    clap_err_result_msg!(
        STANDARD.decode(encoded),
        format!("Could not decode {} from base64", file_or_string)
    )
}
