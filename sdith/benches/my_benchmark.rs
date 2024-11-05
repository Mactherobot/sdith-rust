use criterion::{criterion_group, criterion_main, Criterion};
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, RngCore, Seed, SeedableRng};
use sdith::keygen::keygen;
use sdith::keygen::{PublicKey, SecretKey};
use sdith::signature::signature::Signature;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    // First create master seed
    let mut keygen_seed = [0u8; 16];
    rng.fill_bytes(&mut keygen_seed);
    c.bench_function("keygen", |b| b.iter(|| keygen_bench(&mut rng)));

    let (pk, sk): (PublicKey, SecretKey) = keygen(keygen_seed);

    let mut sign_seed = [0u8; 16];
    let mut sign_salt = [0u8; 32];
    rng.fill_bytes(&mut sign_seed);
    rng.fill_bytes(&mut sign_salt);
    let entropy = (sign_seed, sign_salt);

    let message: Vec<u8> = vec![1, 2, 3, 4];
    c.bench_function("signing", |b| {
        b.iter(|| signing_bench(entropy, sk, message.clone()))
    });

    let signature: Vec<u8> = Signature::sign_message(entropy, sk, &message).unwrap();
    c.bench_function("verification", |b| {
        b.iter(|| verification_bench(pk, &signature))
    });
}

fn keygen_bench(rng: &mut NistPqcAes256CtrRng) {
    let mut keygen_seed = [0u8; 16];
    rng.fill_bytes(&mut keygen_seed);
    keygen(keygen_seed);
}

fn signing_bench(entropy: ([u8; 16], [u8; 32]), sk: SecretKey, message: Vec<u8>) {
    let _signature = Signature::sign_message(entropy, sk, &message.to_vec());
}

fn verification_bench(pk: PublicKey, signature: &Vec<u8>) {
    let _verification = Signature::verify_signature(pk, signature);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
