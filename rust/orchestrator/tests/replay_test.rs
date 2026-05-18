use std::ptr;

#[repr(C)]
pub struct AgentPacket {
    pub payload_ptr: *mut u8,
    pub len: usize,
    pub session_id: u64,
}

extern "C" {
    fn init_enclave_keys();
    fn noise_sign_payload(payload_ptr: *const u8, len: usize, out_sig: *mut u8, session_id: u64) -> i32;
}

const ERR_SEQUENCE_VIOLATION: i32 = 1;

#[test]
fn test_atomic_replay_attack() {
    unsafe { init_enclave_keys() };
    
    let payload = b"atomic replay payload";
    let mut sig = [0u8; 64];
    let session_id = 888888;
    
    // Simulação da primeira tentativa (Zig -> Rust/Enclave)
    let status1 = unsafe {
        noise_sign_payload(payload.as_ptr(), payload.len(), sig.as_mut_ptr(), session_id)
    };
    
    assert_eq!(status1, 0, "A primeira tentativa deveria ter sucesso.");
    
    // Simulação da SEGUNDA tentativa (Replay em microsegundos)
    // O atacante envia o mesmo AgentPacket com o mesmo session_id
    let status2 = unsafe {
        noise_sign_payload(payload.as_ptr(), payload.len(), sig.as_mut_ptr(), session_id)
    };
    
    assert_eq!(status2, ERR_SEQUENCE_VIOLATION, "A segunda tentativa DEVE falhar com Sequence Violation (Autodestroy).");
    println!("✅ Teste de Replay Atômico passou: O sistema detectou e bloqueou o segundo envio do token.");
}
