#![feature(generic_const_exprs)]
// TODO: Can we remove const generics. Currently used by `matrices.rs`

use clap::{Error, Parser};
use cli::Commands;

mod api;
mod arith;
mod cli;
mod constants;
mod keygen;
mod mpc;
mod signature;
mod spec_tests;
mod subroutines;
mod witness;

fn main() {
    let cli = cli::Cli::parse();

    let res = match &cli.command {
        Some(Commands::Keygen(keygen)) => keygen.generate_keys(),
        Some(Commands::Sign(signing)) => signing.sign_message(),
        Some(Commands::Verify(verify)) => verify.verify_signature(),
        None => Err(Error::raw(
            clap::error::ErrorKind::DisplayHelp,
            "No command provided",
        )),
    };

    if res.is_err() {
        eprintln!("Error: {}", res.unwrap_err());
        std::process::exit(1);
    }

    std::process::exit(0);
}
