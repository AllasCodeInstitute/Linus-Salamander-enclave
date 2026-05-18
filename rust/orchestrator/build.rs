fn main() {
    // Procura no root do projeto pela lib do Zig
    println!("cargo:rustc-link-search=native=../../../"); 
    println!("cargo:rustc-link-lib=static=fast_buffer");

    // Procura na pasta do enclave pela lib do Rust
    println!("cargo:rustc-link-search=native=../enclave/target/debug");
    println!("cargo:rustc-link-lib=static=vault_enclave");
    
    // Bibliotecas de sistema do Windows necessárias para Zig e Rust (getrandom)
    println!("cargo:rustc-link-lib=ntdll");
    println!("cargo:rustc-link-lib=bcrypt");
    println!("cargo:rustc-link-lib=advapi32");
    
    // Força a recompilação se as libs mudarem
    println!("cargo:rerun-if-changed=../../../fast_buffer.lib");
    println!("cargo:rerun-if-changed=../enclave/target/debug/vault_enclave.lib");
}
