#[repr(C)]
pub struct EdgeContext {
    pub intent_id: u64,
    pub edge_id: u64,
    pub sequence: u64,
}

extern "C" {
    fn init_enclave_keys();
    fn seal_edge_packet(
        plaintext_ptr: *const u8,
        plaintext_len: usize,
        ctx: *const EdgeContext,
        session_id: u64,
        out_frame: *mut u8,
        out_frame_capacity: usize,
        out_frame_len: *mut usize,
    ) -> i32;
    fn open_edge_packet(
        frame_ptr: *const u8,
        frame_len: usize,
        ctx: *const EdgeContext,
        session_id: u64,
        out_plaintext: *mut u8,
        out_plaintext_capacity: usize,
        out_plaintext_len: *mut usize,
    ) -> i32;
    fn choreograph_packet(
        payload_ptr: *mut u8,
        len: usize,
        in_ctx: *const EdgeContext,
        out_ctx: *const EdgeContext,
        session_id: u64,
    ) -> i32;
}

const AEAD_OVERHEAD: usize = 28;

#[test]
fn test_full_zticam_choreography_flow() {
    unsafe { init_enclave_keys() };
    
    // Simulação do payload original vindo do UIAgent
    let mut plaintext = [0u8; 32];
    plaintext.copy_from_slice(b"user_data_packet_001............");
    
    // --- PASSO 1: UIAgent -> SecurityProxyAgent ---
    // Aresta 10 (UIAgent -> SecurityProxyAgent)
    let edge_1 = EdgeContext { intent_id: 1, edge_id: 10, sequence: 1 };
    let edge_2 = EdgeContext { intent_id: 1, edge_id: 11, sequence: 2 };
    let mut frame = [0u8; 32 + AEAD_OVERHEAD];
    let mut frame_len = 0usize;

    let seal = unsafe {
        seal_edge_packet(
            plaintext.as_ptr(),
            plaintext.len(),
            &edge_1,
            1000,
            frame.as_mut_ptr(),
            frame.len(),
            &mut frame_len,
        )
    };
    assert_eq!(seal, 0, "UIAgent falhou ao selar frame inicial");
    
    println!("Step 1: SecurityProxyAgent processando...");
    let res1 = unsafe {
        choreograph_packet(frame.as_mut_ptr(), frame_len, &edge_1, &edge_2, 1001)
    };
    assert_eq!(res1, 0, "SecurityProxyAgent falhou");

    // --- PASSO 2: SecurityProxyAgent -> GatewayAgent ---
    let edge_3 = EdgeContext { intent_id: 1, edge_id: 12, sequence: 3 };
    println!("Step 2: GatewayAgent processando...");
    let res2 = unsafe {
        choreograph_packet(frame.as_mut_ptr(), frame_len, &edge_2, &edge_3, 1002)
    };
    assert_eq!(res2, 0, "GatewayAgent falhou");

    // --- PASSO 3: GatewayAgent -> ServiceAgent ---
    let edge_4 = EdgeContext { intent_id: 1, edge_id: 13, sequence: 4 };
    let mut replay_frame = frame;
    println!("Step 3: ServiceAgent processando...");
    let res3 = unsafe {
        choreograph_packet(frame.as_mut_ptr(), frame_len, &edge_3, &edge_4, 1003)
    };
    assert_eq!(res3, 0, "ServiceAgent falhou");

    let mut opened = [0u8; 32];
    let mut opened_len = 0usize;
    let open = unsafe {
        open_edge_packet(
            frame.as_ptr(),
            frame_len,
            &edge_4,
            1004,
            opened.as_mut_ptr(),
            opened.len(),
            &mut opened_len,
        )
    };
    assert_eq!(open, 0, "ServiceAgent falhou ao abrir frame final");
    assert_eq!(&opened[..opened_len], &plaintext);

    // --- VERIFICAÇÃO DE REPLAY ---
    // Tentar re-enviar o Passo 3 com o mesmo session_id
    let res_replay = unsafe {
        choreograph_packet(replay_frame.as_mut_ptr(), frame_len, &edge_3, &edge_4, 1003)
    };
    assert_eq!(res_replay, 1, "Proteção contra Replay falhou");
    
    println!("✅ Fluxo ZTICAM completo validado com sucesso!");
}
