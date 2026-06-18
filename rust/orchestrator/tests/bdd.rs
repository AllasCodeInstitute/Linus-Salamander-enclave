// BDD Simulation for Vault Core
// In a real environment, we would use 'cucumber' crate, 
// but for this PoC we simulate the gherkin flow.

use std::ptr;

#[repr(C)]
pub struct AgentPacket {
    pub payload_ptr: *mut u8,
    pub len: usize,
    pub session_id: u64,
}

extern "C" {
    fn poll_packet(out_packet: *mut AgentPacket) -> bool;
    fn init_enclave_keys();
    fn noise_sign_payload(
        payload_ptr: *const u8,
        len: usize,
        out_sig: *mut u8,
        session_id: u64,
    ) -> i32;
}

#[test]
fn scenario_packet_lifecycle_zero_copy_signing() {
    // GIVEN: Enclave is initialized
    unsafe { init_enclave_keys() };

    // WHEN: A packet arrives (simulated via poll_packet)
    let mut packet = AgentPacket {
        payload_ptr: ptr::null_mut(),
        len: 0,
        session_id: 0,
    };

    // We expect false by default in the separated code, 
    // but we can test the function call itself
    let _has_data = unsafe { poll_packet(&mut packet) };

    // THEN: If we had data, we would sign it
    // For the BDD test, we force a payload to validate the signing logic
    let mock_payload = b"agent-request-001";
    let mut signature = [0u8; 64];
    
    let status = unsafe { 
        noise_sign_payload(
            mock_payload.as_ptr(),
            mock_payload.len(),
            signature.as_mut_ptr(),
            70_000,
        )
    };

    assert_eq!(status, 0, "Signing should succeed inside the enclave");
    assert!(signature.iter().any(|&b| b != 0), "Signature should not be empty");
}
