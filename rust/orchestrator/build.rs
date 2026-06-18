fn main() {
    use std::process::Command;

    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"),
    );
    let project_root = manifest_dir
        .join("../..")
        .canonicalize()
        .expect("project root must exist");
    let enclave_target = manifest_dir
        .join("../enclave/target/debug")
        .canonicalize()
        .expect("enclave debug target dir must exist");
    let fast_buffer_lib = project_root.join("fast_buffer.lib");

    if !fast_buffer_lib.exists() {
        let status = Command::new("zig")
            .current_dir(&project_root)
            .args([
                "build-lib",
                "zig/fast_buffer.zig",
                "-target",
                "x86_64-windows-msvc",
                "-O",
                "Debug",
                "--name",
                "fast_buffer",
            ])
            .status()
            .expect("failed to run zig to build fast_buffer.lib");
        assert!(status.success(), "zig failed to build fast_buffer.lib");
    }

    // Procura no root do projeto pela lib do Zig
    println!("cargo:rustc-link-search=native={}", project_root.display());
    println!("cargo:rustc-link-lib=static=fast_buffer");

    // Procura na pasta do enclave pela lib do Rust
    println!(
        "cargo:rustc-link-search=native={}",
        enclave_target.display()
    );
    println!("cargo:rustc-link-lib=static=vault_enclave");
    
    // Bibliotecas de sistema do Windows necessárias para Zig e Rust (getrandom)
    println!("cargo:rustc-link-lib=ntdll");
    println!("cargo:rustc-link-lib=bcrypt");
    println!("cargo:rustc-link-lib=advapi32");

    // Força a recompilação se as libs mudarem
    println!(
        "cargo:rerun-if-changed={}",
        project_root.join("zig/fast_buffer.zig").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        enclave_target.join("vault_enclave.lib").display()
    );
}
