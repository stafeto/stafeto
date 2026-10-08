fn main() {
    // RAM aborts on panic and has no runtime unwind-index consumer. Keep the
    // .eh_frame records for frame proofs while omitting their unused index.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64")
    {
        println!("cargo:rustc-link-arg-bin=ramfs=--no-eh-frame-hdr");
    }
}
