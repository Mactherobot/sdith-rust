//! # SDitH Protocol Command Line Interface
//! 
//! ```
//! Usage: sdith [COMMAND]
//! 
//! Commands:
//!   keygen      SDitH signature protocol -- key generation
//!   sign        SDitH signature protocol -- signing
//!   verify      SDitH signature protocol -- verification
//!   parameters  SDitH signature protocol -- print parameters
//!   help        Print this message or the help of the given subcommand(s)
//! 
//! Options:
//!   -h, --help     Print help
//!   -V, --version  Print version
//! ```
//! 
//! ## Build the CLI
//! 
//! The CLI can be built with the following command:
//! 
//! 
//! ```
//! $ cargo build --release --bin sdith --features [category]
//! ```
//! 
//! ## Keygen
//! 
//! ```
//! $ sdith keygen -o key
//! Seed: wmcuKiOGX/OXRBdC4dimmA==
//! Public key saved to "key.pub"
//! Secret key saved to "key"
//! ```
//! 
//! ## Signing
//! 
//! ```
//! $ sdith sign --msg "hello world" --sk key > signature.txt
//! Signing message.
//! Reading Secret Key from file: key
//! Seed: jLsixeA3XNdwoFcIvMWwAw==
//! Salt: zZma69OYka48jJGwuI3NTD8tpkcNfTdLtP5O43XXgLo=
//! ```
//! 
//! ## Verification
//! 
//! ```
//! $ sdith verify --pk key.pub --signature signature.txt
//! Verifying message.
//! Reading Public Key from file: key.pub
//! Reading Signature from file: signature.txt
//! Signature is valid: true
//! ```

use clap::{CommandFactory, Parser, Subcommand};
use parameters::Parameters;
use colored::Colorize as _;
use keygen::Keygen;
use signing::Signing;
use verifying::Verifying;

mod parameters;
mod keygen;
mod utilities;
mod signing;
mod verifying;

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

fn main() {
    let cli = Cli::parse();

    let res = match &cli.command {
        Some(Commands::Keygen(keygen)) => keygen.generate_keys(),
        Some(Commands::Sign(signing)) => signing.sign_message(),
        Some(Commands::Verify(verify)) => verify.verify_signature(),
        Some(Commands::Parameters(parameters)) => parameters.print_info(),
        // Print help
        None => {
            let _ = Cli::command().print_help();
            Ok(())
        }
    };

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string().red());
        std::process::exit(1);
    }

    std::process::exit(0);
}
