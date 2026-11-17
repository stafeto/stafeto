//! Tells the crates that compile littlefs where its sources are: `DEP_LITTLEFS_ROOT`.

fn main() {
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo sets the manifest directory");
    println!("cargo:root={root}");
    println!("cargo:rerun-if-changed=build.rs");
}
