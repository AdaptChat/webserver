use std::{env, fs, path::PathBuf};

fn main() {
    let dest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("secret.key");

    if let Ok(src) = env::var("SECRET_KEY_PATH") {
        let src = PathBuf::from(&src);
        fs::copy(&src, &dest)
            .unwrap_or_else(|e| panic!("failed to copy secret key from {}: {e}", src.display()));
        println!("cargo::rerun-if-changed={src}", src = src.display());
    }

    println!("cargo::rerun-if-changed=secret.key");
    println!("cargo::rerun-if-env-changed=SECRET_KEY_PATH");
}
