use rustc_version::{version_meta, Channel};

fn main() {
    setup_doc_nightly();

    // Load the environment variables from the .env file
    let cat = if cfg!(feature = "category_three") {
        "three"
    } else if cfg!(feature = "category_five") {
        "five"
    } else {
        "one"
    };

    // Notify the user of the category being used
    println!("cargo:warning=Running with category {cat}");

    // Check if feature flag is blake3 as it is not supported for categories above 1
    if (cfg!(feature = "xof_blake3") || cfg!(feature = "hash_blake3")) && cat != "one" {
        panic!("Blake3 only supports 128 bit security. 256 is required for categories above 1.")
    }

    // Notify the developer about optimisations
    if cfg!(feature = "simd") {
        println!("cargo:warning=SIMD enabled");
    }
    if cfg!(feature = "parallel") {
        println!("cargo:warning=Parallel enabled");
    }
    if cfg!(feature = "jemalloc") {
        println!("cargo:warning=Jemalloc enabled");
    }
    if cfg!(feature = "mimalloc") {
        println!("cargo:warning=Mimalloc enabled");
    }
    if cfg!(feature = "merkle_batching") {
        println!("cargo:warning=Merkle tree batching enabled");
    }
}

/// Based on https://stackoverflow.com/a/70914430
/// Set cfg flags depending on the release channel
/// As doc is always built on nightly, we can set the cfg flag enabling the nightly feature `doc-auto-cfg`
fn setup_doc_nightly() {
    // Set cfg flags depending on release channel
    let channel = match version_meta().unwrap().channel {
        Channel::Stable => "CHANNEL_STABLE",
        Channel::Beta => "CHANNEL_BETA",
        Channel::Nightly => "CHANNEL_NIGHTLY",
        Channel::Dev => "CHANNEL_DEV",
    };
    println!("cargo:rustc-cfg={}", channel)
}
