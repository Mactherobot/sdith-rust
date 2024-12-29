//! # SDitH Protocol Command Line Interface
//! 
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
//! 
//! ## Build the CLI
//! 
//! The CLI can be built with the following command:
//! 
//! ```
//! cargo build --release --bin sdith --features [category]
//! ```

use clap::{CommandFactory, Parser};
use cli::Commands;
use colored::Colorize as _;

mod cli;

fn main() {
    let cli = cli::Cli::parse();

    let res = match &cli.command {
        Some(Commands::Keygen(keygen)) => keygen.generate_keys(),
        Some(Commands::Sign(signing)) => signing.sign_message(),
        Some(Commands::Verify(verify)) => verify.verify_signature(),
        Some(Commands::Parameters(parameters)) => parameters.print_info(),
        // Print help
        None => {
            let _ = cli::Cli::command().print_help();
            Ok(())
        }
    };

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string().red());
        std::process::exit(1);
    }

    std::process::exit(0);
}
