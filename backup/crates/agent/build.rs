fn main() {
    // The agent reports its target so the server can offer the matching build.
    println!(
        "cargo:rustc-env=FENRIR_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!("cargo:rerun-if-changed=build.rs");
}
