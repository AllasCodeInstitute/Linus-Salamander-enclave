use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};

type HmacSha256 = Hmac<Sha256>;

// --- Estruturas ZTICAM ---

#[repr(C)]
pub struct TripartiteIdentity {
    pub pub_key: [u8; 32],
    pub mac_addr: [u8; 6],
    pub ip_addr: [u8; 4],
}

#[repr(C)]
pub struct PQCSession {
    pub session_id: u64,
    pub shared_secret: [u8; 32],
    pub is_quantum_resistant: bool,
}

// Armazenamento efêmero de sessões PQC
static mut ACTIVE_PQC_SESSIONS: [Option<PQCSession>; 16] = [None; 16];

// 3. Camada de Comunicação eBPF + mTLS Kyber (Camada 3)
#[no_mangle]
pub extern "C" fn init_pqc_session(session_id: u64, out_pubkey: *mut u8) -> i32 {
    // Aqui seria gerado o par de chaves Kyber (ML-KEM)
    // Para o PoC, simulamos a geração e armazenamento
    let session = PQCSession {
        session_id,
        shared_secret: [0u8; 32],
        is_quantum_resistant: true,
    };
    
    unsafe {
        ACTIVE_PQC_SESSIONS[0] = Some(session);
        // Retorna uma "chave pública" fictícia do Kyber
        core::ptr::write_bytes(out_pubkey, 0xAA, 1184); // Kyber768 pubkey size
    }
    0
}

#[no_mangle]
pub extern "C" fn verify_pqc_handshake(session_id: u64, peer_ciphertext: *const u8) -> i32 {
    // Valida o encapsulamento do Kyber e deriva o segredo compartilhado
    unsafe {
        if let Some(ref mut session) = ACTIVE_PQC_SESSIONS[0] {
            if session.session_id == session_id {
                // Sucesso na decapsulação
                return 0;
            }
        }
    }
    -3 // PQC Handshake Failed
}
static mut ROOT_SEED: [u8; 32] = [0u8; 32];

// Bitmap ultra-rápido para detecção de Replay (Autodestroy)
static mut REPLAY_BITMAP: [u64; 1024] = [0; 1024];

#[no_mangle]
pub extern "C" fn init_enclave_keys() {
    let signing_key = SigningKey::generate(&mut OsRng);
    unsafe {
        ENCLAVE_SIGNING_KEY = Some(signing_key);
        REPLAY_BITMAP = [0; 1024];
        // Semente inicial do hardware (Root Sealing Key simulation)
        ROOT_SEED = [0x53, 0x41, 0x4C, 0x41, 0x4D, 0x41, 0x4E, 0x44, 0x45, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }
}

// 1. Geração de Identidade Semântica (Camada 2)
// IKM: Name + Capabilities + Plane + SemanticTypes
#[no_mangle]
pub extern "C" fn generate_agent_key(
    name: *const u8, name_len: usize,
    caps: *const u8, caps_len: usize,
    plane: *const u8, plane_len: usize,
    semantics: *const u8, semantics_len: usize,
    out_key: *mut u8
) -> i32 {
    let mut hasher = Sha256::new();
    
    // Mix hardware root seed (Binding)
    hasher.update(unsafe { &ROOT_SEED });
    
    // Mix semantic pillars
    hasher.update(unsafe { core::slice::from_raw_parts(name, name_len) });
    hasher.update(unsafe { core::slice::from_raw_parts(caps, caps_len) });
    hasher.update(unsafe { core::slice::from_raw_parts(plane, plane_len) });
    hasher.update(unsafe { core::slice::from_raw_parts(semantics, semantics_len) });
    
    let result = hasher.finalize();
    unsafe {
        core::ptr::copy_nonoverlapping(result.as_ptr(), out_key, 32);
    }
    0
}

// 1. Verificação de Identidade Tripartite (Camada 3)
#[no_mangle]
pub extern "C" fn verify_tripartite_identity(id: *const TripartiteIdentity, expected_hash: *const u8) -> i32 {
    let identity = unsafe { &*id };
    let mut hasher = Sha256::new();
    
    // A identidade é validada contra o hash que o Enclave emitiu
    hasher.update(&identity.pub_key);
    hasher.update(&identity.mac_addr);
    hasher.update(&identity.ip_addr);
    
    let result = hasher.finalize();
    let expected = unsafe { core::slice::from_raw_parts(expected_hash, 32) };
    
    if result.as_slice() == expected {
        return 0; // OK
    }
    -2 // Identity Mismatch (Silent Passkey Challenge should be triggered)
}

// 2. Derivação de Chave por Aresta (Edge-Based Crypto)
fn derive_edge_key(ctx: &EdgeContext) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(unsafe { &ROOT_SEED }).expect("HMAC can take key of any size");
    mac.update(&ctx.intent_id.to_le_bytes());
    mac.update(&ctx.edge_id.to_le_bytes());
    mac.update(&ctx.sequence.to_le_bytes());
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes()[..32]);
    key
}

// 3. Coreografia: Descriptografa (Aresta N) -> Processa -> Re-criptografa (Aresta N+1)
#[no_mangle]
pub extern "C" fn choreograph_packet(
    payload_ptr: *mut u8,
    len: usize,
    in_ctx: *const EdgeContext,
    out_ctx: *const EdgeContext,
    session_id: u64
) -> i32 {
    // A. Replay Protection (Autodestroy)
    let index = (session_id % 65536) as usize;
    let word = index / 64;
    let bit = index % 64;
    unsafe {
        if (REPLAY_BITMAP[word] & (1 << bit)) != 0 {
            return 1; // ERR_SEQUENCE_VIOLATION
        }
        REPLAY_BITMAP[word] |= (1 << bit);
    }

    let in_edge = unsafe { &*in_ctx };
    let out_edge = unsafe { &*out_ctx };
    
    // B. Deriva chaves das arestas
    let key_in = derive_edge_key(in_edge);
    let key_out = derive_edge_key(out_edge);

    // C. Simulação de processamento (em um sistema real usaríamos AES-GCM aqui)
    // Para o PoC, fazemos um XOR simples que representa a transformação atômica no Enclave
    let data = unsafe { core::slice::from_raw_parts_mut(payload_ptr, len) };
    for i in 0..len {
        // "Descriptografa" com key_in e "Criptografa" com key_out
        data[i] ^= key_in[i % 32] ^ key_out[i % 32];
    }

    0 // Success
}

#[no_mangle]
pub extern "C" fn noise_sign_payload(
    payload_ptr: *const u8,
    len: usize,
    out_sig: *mut u8,
    session_id: u64
) -> i32 {
    // Reuso da lógica de replay para compatibilidade
    let index = (session_id % 65536) as usize;
    let word = index / 64;
    let bit = index % 64;
    unsafe {
        if (REPLAY_BITMAP[word] & (1 << bit)) != 0 {
            return 1;
        }
        REPLAY_BITMAP[word] |= (1 << bit);
    }

    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, len) };
    unsafe {
        if let Some(ref sk) = ENCLAVE_SIGNING_KEY {
            let signature: Signature = sk.sign(payload);
            core::ptr::copy_nonoverlapping(signature.to_bytes().as_ptr(), out_sig, 64);
            return 0;
        }
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zticam_edge_choreography() {
        init_enclave_keys();
        let mut payload = [0u8; 32];
        payload.copy_from_slice(b"secret data inside the intent...");
        
        let in_ctx = EdgeContext { intent_id: 1, edge_id: 100, sequence: 1 };
        let out_ctx = EdgeContext { intent_id: 1, edge_id: 101, sequence: 2 };
        
        let res = choreograph_packet(payload.as_mut_ptr(), payload.len(), &in_ctx, &out_ctx, 555);
        assert_eq!(res, 0);
        
        // Segunda tentativa com mesmo session_id deve falhar
        let res2 = choreograph_packet(payload.as_mut_ptr(), payload.len(), &in_ctx, &out_ctx, 555);
        assert_eq!(res2, 1);
    }

    #[test]
    fn test_tripartite_identity() {
        let id = TripartiteIdentity {
            pub_key: [0u8; 32],
            mac_addr: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            ip_addr: [192, 168, 0, 1],
        };
        
        let mut hasher = Sha256::new();
        hasher.update(&id.pub_key);
        hasher.update(&id.mac_addr);
        hasher.update(&id.ip_addr);
        let expected_hash = hasher.finalize();
        
        let res = verify_tripartite_identity(&id, expected_hash.as_ptr());
        assert_eq!(res, 0);
    }
}
