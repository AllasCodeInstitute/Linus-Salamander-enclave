static ENCLAVE_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[no_mangle]
pub extern "C" fn init_enclave_keys() {
    #[cfg(test)]
    {
        reset_enclave_for_tests();
    }

    #[cfg(not(test))]
    {
        // Refuse re-initialization after first call to prevent replay bitmap clear
        // and root seed reset (CVE-LSES-004).
        if ENCLAVE_INITIALIZED
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            return;
        }

        if let Ok(mut guard) = state().lock() {
            guard.signing_key = Some(SigningKey::generate(&mut OsRng));
            guard.replay_bitmap = [0; 1024];
            // CVE-LSES-001: Generate a cryptographically random root seed.
            // Never reset to the static "SALAMANDER" constant.
            OsRng.fill_bytes(&mut guard.root_seed);
        }
    }
}

#[cfg(test)]
pub fn reset_enclave_for_tests() {
    ENCLAVE_INITIALIZED.store(false, std::sync::atomic::Ordering::SeqCst);
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    guard.signing_key = Some(SigningKey::generate(&mut OsRng));
    guard.replay_bitmap = [0; 1024];
    OsRng.fill_bytes(&mut guard.root_seed);
}
