// Security Testing
// Focuses on robustness against malformed data and pointer safety.

extern "C" {
    fn init_enclave_keys();
    fn noise_sign_payload(
        payload_ptr: *const u8,
        len: usize,
        out_sig: *mut u8,
        session_id: u64,
    ) -> i32;
}

const ERR_NULL_POINTER: i32 = -2;

#[test]
fn test_security_null_pointer_handling() {
    unsafe { init_enclave_keys() };
    let mut sig = [0u8; 64];
    
    // Test with null payload pointer
    // Note: Rust references usually prevent this, but FFI allows it.
    // Our C-ABI implementation in Rust uses `from_raw_parts` which is unsafe.
    // A robust implementation should check for null.
    
    // This is a "Positive/Negative" security test. 
    // We expect the system to NOT crash or at least return error if we added checks.
    // For now, we validate standard behavior.
    let status = unsafe {
        noise_sign_payload(std::ptr::null(), 16, sig.as_mut_ptr(), 74_000)
    };

    assert_eq!(status, ERR_NULL_POINTER);
}

#[test]
fn test_security_empty_payload() {
    unsafe { init_enclave_keys() };
    let mut sig = [0u8; 64];
    let payload: [u8; 0] = [];
    
    let status = unsafe {
        noise_sign_payload(payload.as_ptr(), 0, sig.as_mut_ptr(), 7777)
    };
    
    // Signing an empty payload should still work (it's a valid message of len 0)
    assert_eq!(status, 0);
}

#[test]
fn test_security_key_isolation() {
    // Conceptual Security Test:
    // Ensure the keypair is not accessible via standard memory read.
    // In our PoC, it's a static mut. In a real SGX enclave, this would be validated 
    // by the hardware attestation.
}
