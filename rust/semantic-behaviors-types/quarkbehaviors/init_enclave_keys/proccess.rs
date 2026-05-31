#[no_mangle]
pub extern "C" fn init_enclave_keys() {
    if let Ok(mut guard) = state().lock() {
        guard.signing_key = Some(SigningKey::generate(&mut OsRng));
        guard.replay_bitmap = [0; 1024];
        guard.root_seed = ROOT_SEED_DEFAULT;
    }
}
