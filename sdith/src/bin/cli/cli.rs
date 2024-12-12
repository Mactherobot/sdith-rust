use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Error, Parser, Subcommand};
use colored::Colorize as _;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use sdith::{
    constants::{
        params::{self, PARAM_SALT_SIZE, PARAM_SEED_SIZE},
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
#[command(version, about("SDitH signature protocol"))]
#[cfg_attr(
    not(any(feature = "category_three", feature = "category_five")),
    command(about("SDitH signature protocol\nNIST Category ONE variant"))
)]
#[cfg_attr(
    feature = "category_three",
    command(about("SDitH signature protocol\nNIST Category THREE variant"))
)]
#[cfg_attr(
    feature = "category_five",
    command(about("SDitH signature protocol\nNIST Category FIVE variant"))
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Keygen(Keygen),
    Sign(Signing),
    Verify(Verifying),
    Parameters(Parameters),
}

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
                false => "Signature is valid: ".red(),
            }
        );

        println!("{}", is_valid);

        Ok(())
    }
}

// Utility functions

fn print_title(title: &str) {
    eprintln!("{}", title.green().bold());
}

/// Returns a seed. If no seed is provided, a random seed is generated. Returns true if seed is random.
fn get_seed(_seed: Option<&String>) -> Result<Seed, Error> {
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

    if _seed.is_none() {
        eprintln!("{}: {}", "Seed".blue(), STANDARD.encode(seed));
    }

    Ok(seed)
}

fn get_salt(_salt: Option<&String>) -> Result<Salt, Error> {
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

    if _salt.is_none() {
        eprintln!("{}: {}", "Salt".blue(), STANDARD.encode(salt));
    }

    Ok(salt)
}

/// Checks if the input is a file or a string. Returns the decoded string from the file or the input string.
fn get_decoded_string_from_file_or_string(
    file_or_string: String,
    title: Option<String>,
) -> Result<Vec<u8>, Error> {
    let path = Path::new(&file_or_string);
    let read_title = match &title {
        Some(title) => format!("Reading {} from file", title).blue(),
        None => "Reading from file".blue(),
    };

    let encoded = if path.exists() {
        eprintln!("{}: {}", read_title, path.display());
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        file_or_string.clone()
    };

    clap_err_result_msg!(
        STANDARD.decode(encoded),
        format!(
            "Could not decode {} from base64",
            match title {
                Some(title) => title,
                None => "input".to_string(),
            }
        )
    )
}
