use std::ptr;

#[repr(C)]
pub struct TripartiteIdentity {
    pub pub_key: [u8; 32],
    pub mac_addr: [u8; 6],
    pub ip_addr: [u8; 4],
}

#[repr(C)]
pub struct EdgeContext {
    pub intent_id: u64,
    pub edge_id: u64,
    pub sequence: u64,
}

extern "C" {
    fn init_enclave_keys();
    fn choreograph_packet(
        payload_ptr: *mut u8,
        len: usize,
        in_ctx: *const EdgeContext,
        out_ctx: *const EdgeContext,
        session_id: u64
    ) -> i32;
    fn verify_tripartite_identity(id: *const TripartiteIdentity, expected_hash: *const u8) -> i32;
}

#[test]
fn test_full_zticam_choreography_flow() {
    unsafe { init_enclave_keys() };
    
    // Simulação do payload original vindo do UIAgent
    let mut payload = [0u8; 32];
    payload.copy_from_slice(b"user_data_packet_001............");
    
    // --- PASSO 1: UIAgent -> SecurityProxyAgent ---
    // Aresta 10 (UIAgent -> SecurityProxyAgent)
    let edge_1 = EdgeContext { intent_id: 1, edge_id: 10, sequence: 1 };
    let edge_2 = EdgeContext { intent_id: 1, edge_id: 11, sequence: 2 };
    
    println!("Step 1: SecurityProxyAgent processando...");
    let res1 = unsafe {
        choreograph_packet(payload.as_mut_ptr(), payload.len(), &edge_1, &edge_2, 1001)
    };
    assert_eq!(res1, 0, "SecurityProxyAgent falhou");

    // --- PASSO 2: SecurityProxyAgent -> GatewayAgent ---
    let edge_3 = EdgeContext { intent_id: 1, edge_id: 12, sequence: 3 };
    println!("Step 2: GatewayAgent processando...");
    let res2 = unsafe {
        choreograph_packet(payload.as_mut_ptr(), payload.len(), &edge_2, &edge_3, 1002)
    };
    assert_eq!(res2, 0, "GatewayAgent falhou");

    // --- PASSO 3: GatewayAgent -> ServiceAgent ---
    let edge_4 = EdgeContext { intent_id: 1, edge_id: 13, sequence: 4 };
    println!("Step 3: ServiceAgent processando...");
    let res3 = unsafe {
        choreograph_packet(payload.as_mut_ptr(), payload.len(), &edge_3, &edge_4, 1003)
    };
    assert_eq!(res3, 0, "ServiceAgent falhou");

    // --- VERIFICAÇÃO DE REPLAY ---
    // Tentar re-enviar o Passo 3 com o mesmo session_id
    let res_replay = unsafe {
        choreograph_packet(payload.as_mut_ptr(), payload.len(), &edge_3, &edge_4, 1003)
    };
    assert_eq!(res_replay, 1, "Proteção contra Replay falhou");
    
    println!("✅ Fluxo ZTICAM completo validado com sucesso!");
}
