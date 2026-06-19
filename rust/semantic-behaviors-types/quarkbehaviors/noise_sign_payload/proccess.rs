// DEPRECATED: This function signs raw bytes with no scope, recipient, or
// operation binding. A MIASMA worm that obtains this enclave's signing key can
// use it to sign ANY payload for ANY target. Use `noise_sign_scoped_payload` +
// `noise_verify_scoped_signature` for all new code: they bind every signature
// to a specific recipient agent and operation, breaking the worm's forwarding path.
#[no_mangle]
pub extern "C" fn noise_sign_payload(
    payload_ptr: *const u8,
    len: usize,
    out_sig: *mut u8,
    session_id: u64,
) -> i32 {
    if payload_ptr.is_null() || out_sig.is_null() {
        return ERR_NULL_POINTER;
    }

    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    if !guard.try_mark_replay(session_id) {
        return ERR_REPLAY;
    }

    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, len) };
    if let Some(sk) = &guard.signing_key {
        let signature = sk.sign(payload);
        unsafe { core::ptr::copy_nonoverlapping(signature.to_bytes().as_ptr(), out_sig, 64) };
        return 0;
    }
    ERR_STATE
}
