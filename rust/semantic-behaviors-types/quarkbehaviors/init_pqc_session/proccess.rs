#[no_mangle]
pub extern "C" fn init_pqc_session(session_id: u64, out_pubkey: *mut u8) -> i32 {
    if out_pubkey.is_null() {
        return ERR_NULL_POINTER;
    }

    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    guard.pqc_sessions[0] = Some(PQCSession {
        session_id,
        shared_secret: [0u8; 32],
        is_quantum_resistant: true,
    });

    unsafe { core::ptr::write_bytes(out_pubkey, 0xAA, 1184) };
    0
}
