use const_gen::*;
use std::{env, fs, path::Path};

fn main() {
    // Use the OUT_DIR environment variable to get an
    // appropriate path.
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    // Now we'll generate the const declarations. We're also
    // going to test with some primitive types.
    let const_declarations = vec![const_declaration!(#[doc = "Testing"] pub(crate) TEST_U8 = 27u8)].join("\n");

    // Lastly, output to the destination file.
    fs::write(&dest_path, const_declarations).unwrap();
}


fn build_constants
