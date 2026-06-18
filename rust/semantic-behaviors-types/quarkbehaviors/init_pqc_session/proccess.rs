// CVE-LSES-007: PQC (ML-KEM-768 / Kyber) is NOT yet implemented.
// The API surface is reserved for future integration. Callers must not
// assume quantum resistance is provided until this function returns 0
// with a real ML-KEM public key.
const ERR_NOT_IMPLEMENTED: i32 = -10;

#[no_mangle]
pub extern "C" fn init_pqc_session(_session_id: u64, _out_pubkey: *mut u8) -> i32 {
    ERR_NOT_IMPLEMENTED
}
