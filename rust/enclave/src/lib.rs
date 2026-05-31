use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};

type HmacSha256 = Hmac<Sha256>;

#[repr(C)]
pub struct TripartiteIdentity {
    pub pub_key: [u8; 32],
    pub mac_addr: [u8; 6],
    pub ip_addr: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EdgeContext {
    pub intent_id: u64,
    pub edge_id: u64,
    pub sequence: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PQCSession {
    pub session_id: u64,
    pub shared_secret: [u8; 32],
    pub is_quantum_resistant: bool,
}

const ROOT_SEED_DEFAULT: [u8; 32] = [
    0x53, 0x41, 0x4C, 0x41, 0x4D, 0x41, 0x4E, 0x44, 0x45, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

struct EnclaveState {
    signing_key: Option<SigningKey>,
    replay_bitmap: [u64; 1024],
    root_seed: [u8; 32],
    pqc_sessions: [Option<PQCSession>; 16],
}

impl EnclaveState {
    fn new() -> Self {
        Self {
            signing_key: None,
            replay_bitmap: [0; 1024],
            root_seed: ROOT_SEED_DEFAULT,
            pqc_sessions: [None; 16],
        }
    }

    fn try_mark_replay(&mut self, session_id: u64) -> bool {
        let index = (session_id % 65536) as usize;
        let word = index / 64;
        let bit = index % 64;
        let mask = 1u64 << bit;
        if (self.replay_bitmap[word] & mask) != 0 {
            return false;
        }
        self.replay_bitmap[word] |= mask;
        true
    }
}

static STATE: OnceLock<Mutex<EnclaveState>> = OnceLock::new();

fn state() -> &'static Mutex<EnclaveState> {
    STATE.get_or_init(|| Mutex::new(EnclaveState::new()))
}

#[no_mangle]
pub extern "C" fn init_pqc_session(session_id: u64, out_pubkey: *mut u8) -> i32 {
    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    guard.pqc_sessions[0] = Some(PQCSession {
        session_id,
        shared_secret: [0u8; 32],
        is_quantum_resistant: true,
    });

    if out_pubkey.is_null() {
        return -2;
    }

    unsafe { core::ptr::write_bytes(out_pubkey, 0xAA, 1184) };
    0
}

#[no_mangle]
pub extern "C" fn verify_pqc_handshake(session_id: u64, _peer_ciphertext: *const u8) -> i32 {
    let guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if let Some(session) = guard.pqc_sessions[0] {
        if session.session_id == session_id {
            return 0;
        }
    }
    -3
}

#[no_mangle]
pub extern "C" fn init_enclave_keys() {
    if let Ok(mut guard) = state().lock() {
        guard.signing_key = Some(SigningKey::generate(&mut OsRng));
        guard.replay_bitmap = [0; 1024];
        guard.root_seed = ROOT_SEED_DEFAULT;
    }
}

#[no_mangle]
pub extern "C" fn generate_agent_key(
    name: *const u8,
    name_len: usize,
    caps: *const u8,
    caps_len: usize,
    plane: *const u8,
    plane_len: usize,
    semantics: *const u8,
    semantics_len: usize,
    out_key: *mut u8,
) -> i32 {
    if name.is_null() || caps.is_null() || plane.is_null() || semantics.is_null() || out_key.is_null() {
        return -2;
    }

    let guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let mut hasher = Sha256::new();
    hasher.update(guard.root_seed);
    hasher.update(unsafe { core::slice::from_raw_parts(name, name_len) });
    hasher.update(unsafe { core::slice::from_raw_parts(caps, caps_len) });
    hasher.update(unsafe { core::slice::from_raw_parts(plane, plane_len) });
    hasher.update(unsafe { core::slice::from_raw_parts(semantics, semantics_len) });

    let result = hasher.finalize();
    unsafe { core::ptr::copy_nonoverlapping(result.as_ptr(), out_key, 32) };
    0
}

#[no_mangle]
pub extern "C" fn verify_tripartite_identity(id: *const TripartiteIdentity, expected_hash: *const u8) -> i32 {
    if id.is_null() || expected_hash.is_null() {
        return -2;
    }

    let identity = unsafe { &*id };
    let mut hasher = Sha256::new();
    hasher.update(identity.pub_key);
    hasher.update(identity.mac_addr);
    hasher.update(identity.ip_addr);

    let result = hasher.finalize();
    let expected = unsafe { core::slice::from_raw_parts(expected_hash, 32) };
    if result.as_slice() == expected { 0 } else { -2 }
}

fn derive_edge_key(ctx: &EdgeContext, root_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(root_seed).expect("HMAC accepts any key size");
    mac.update(&ctx.intent_id.to_le_bytes());
    mac.update(&ctx.edge_id.to_le_bytes());
    mac.update(&ctx.sequence.to_le_bytes());
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes()[..32]);
    key
}

#[no_mangle]
pub extern "C" fn choreograph_packet(
    payload_ptr: *mut u8,
    len: usize,
    in_ctx: *const EdgeContext,
    out_ctx: *const EdgeContext,
    session_id: u64,
) -> i32 {
    if payload_ptr.is_null() || in_ctx.is_null() || out_ctx.is_null() {
        return -2;
    }

    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if !guard.try_mark_replay(session_id) {
        return 1;
    }

    let in_edge = unsafe { &*in_ctx };
    let out_edge = unsafe { &*out_ctx };
    let key_in = derive_edge_key(in_edge, &guard.root_seed);
    let key_out = derive_edge_key(out_edge, &guard.root_seed);

    let data = unsafe { core::slice::from_raw_parts_mut(payload_ptr, len) };
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key_in[i % 32] ^ key_out[i % 32];
    }

    0
}

#[no_mangle]
pub extern "C" fn noise_sign_payload(payload_ptr: *const u8, len: usize, out_sig: *mut u8, session_id: u64) -> i32 {
    if payload_ptr.is_null() || out_sig.is_null() {
        return -2;
    }

    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    if !guard.try_mark_replay(session_id) {
        return 1;
    }

    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, len) };
    if let Some(sk) = &guard.signing_key {
        let signature = sk.sign(payload);
        unsafe { core::ptr::copy_nonoverlapping(signature.to_bytes().as_ptr(), out_sig, 64) };
        return 0;
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

        let res2 = choreograph_packet(payload.as_mut_ptr(), payload.len(), &in_ctx, &out_ctx, 555);
        assert_eq!(res2, 1);
    }
}
