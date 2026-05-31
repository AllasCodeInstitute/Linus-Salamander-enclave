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
