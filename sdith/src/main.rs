use clap::{Error, Parser};
use cli::Commands;
use colored::Colorize as _;

pub mod cli;

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
        eprintln!("{}", res.unwrap_err().to_string().red());
        std::process::exit(1);
    }

    std::process::exit(0);
}
