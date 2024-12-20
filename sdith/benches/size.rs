#![allow(dead_code)]
use std::{
    env,
    io::{stderr, Write},
};

use colored::Colorize as _;
use criterion::Criterion;
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed};
use rand::{RngCore as _, SeedableRng as _};
use rsdith::{keygen::keygen, signature, utils::marshalling::Marshalling as _};
use stats_ci::{Confidence, StatisticsOps};

const ITER: usize = 250;

pub(crate) fn proof_size_benchmark(_c: &mut Criterion) {
    // Only run this benchmark if the "size" id is passed as an argument
    let mut args = env::args_os();
    if !args.any(|arg| arg == "size") {
        return;
    }

    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    let mut root_seed = rsdith::constants::types::Seed::default();
    let mut salt = [0u8; rsdith::constants::params::PARAM_SALT_SIZE];
    rng.fill_bytes(&mut root_seed);
    rng.fill_bytes(&mut salt);
    let (_, sk) = keygen(root_seed);

    let mut msg = vec![0u8; 100];

    let mut stats = stats_ci::mean::Arithmetic::<f64>::new();

    eprint!("Measuring signature size for {} iterations", ITER);
    stderr().flush().unwrap();

    (0..ITER).into_iter().for_each(|_| {
        rng.fill_bytes(&mut msg);
        let signature = signature::Signature::sign_message((root_seed, salt), &sk, &msg).unwrap();
        let bytes = signature.serialise().len();
        stats
            .append(bytes as f64)
            .expect("Could not append to stats");
    });
    eprint!("\r{}", "\x1B[2K"); // Clear the line

    let conf = Confidence::new(0.95);
    let ci = stats.ci_mean(conf).unwrap();

    println!(
        "{}{}size:   [{} B {} B {} B] {}",
        "size/signature".green(),
        " ".repeat(10),
        format!("{:.3}", ci.low().unwrap()).bright_black(),
        format!("{:.3}", stats.sample_mean()).bold(),
        format!("{:.3}", ci.high().unwrap()).bright_black(),
        format!("ci: {:.0}%", conf.percent()).bright_black(),
    );
}
