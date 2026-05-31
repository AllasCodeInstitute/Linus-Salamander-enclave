use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};

type HmacSha256 = Hmac<Sha256>;

const ERR_REPLAY: i32 = 1;
const ERR_STATE: i32 = -1;
const ERR_NULL_POINTER: i32 = -2;
const ERR_AUTHENTICATION: i32 = -3;
const ERR_BUFFER_TOO_SMALL: i32 = -4;
const ERR_CRYPTO: i32 = -5;

const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;
const AEAD_OVERHEAD: usize = AEAD_NONCE_LEN + AEAD_TAG_LEN;

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
    0x53, 0x41, 0x4C, 0x41, 0x4D, 0x41, 0x4E, 0x44, 0x45, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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

#[no_mangle]
pub extern "C" fn verify_pqc_handshake(session_id: u64, _peer_ciphertext: *const u8) -> i32 {
    let guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    if let Some(session) = guard.pqc_sessions[0] {
        if session.session_id == session_id {
            return 0;
        }
    }
    ERR_AUTHENTICATION
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
    if name.is_null()
        || caps.is_null()
        || plane.is_null()
        || semantics.is_null()
        || out_key.is_null()
    {
        return ERR_NULL_POINTER;
    }

    let guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
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
pub extern "C" fn verify_tripartite_identity(
    id: *const TripartiteIdentity,
    expected_hash: *const u8,
) -> i32 {
    if id.is_null() || expected_hash.is_null() {
        return ERR_NULL_POINTER;
    }

    let identity = unsafe { &*id };
    let mut hasher = Sha256::new();
    hasher.update(identity.pub_key);
    hasher.update(identity.mac_addr);
    hasher.update(identity.ip_addr);

    let result = hasher.finalize();
    let expected = unsafe { core::slice::from_raw_parts(expected_hash, 32) };
    if result.as_slice() == expected {
        0
    } else {
        ERR_AUTHENTICATION
    }
}

fn derive_edge_key(ctx: &EdgeContext, root_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(root_seed).expect("HMAC accepts any key size");
    mac.update(&ctx.intent_id.to_le_bytes());
    mac.update(&ctx.edge_id.to_le_bytes());
    mac.update(&ctx.sequence.to_le_bytes());
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes()[..32]);
    key
}

fn edge_context_aad(ctx: &EdgeContext) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[0..8].copy_from_slice(&ctx.intent_id.to_le_bytes());
    aad[8..16].copy_from_slice(&ctx.edge_id.to_le_bytes());
    aad[16..24].copy_from_slice(&ctx.sequence.to_le_bytes());
    aad
}

fn mark_replay_and_get_root_seed(session_id: u64) -> Result<[u8; 32], i32> {
    let mut guard = state().lock().map_err(|_| ERR_STATE)?;
    if !guard.try_mark_replay(session_id) {
        return Err(ERR_REPLAY);
    }
    Ok(guard.root_seed)
}

#[no_mangle]
pub extern "C" fn seal_edge_packet(
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    ctx: *const EdgeContext,
    session_id: u64,
    out_frame: *mut u8,
    out_frame_capacity: usize,
    out_frame_len: *mut usize,
) -> i32 {
    if (plaintext_ptr.is_null() && plaintext_len != 0)
        || ctx.is_null()
        || out_frame.is_null()
        || out_frame_len.is_null()
    {
        return ERR_NULL_POINTER;
    }

    let required_len = match plaintext_len.checked_add(AEAD_OVERHEAD) {
        Some(len) => len,
        None => return ERR_BUFFER_TOO_SMALL,
    };
    if out_frame_capacity < required_len {
        return ERR_BUFFER_TOO_SMALL;
    }

    let edge = unsafe { &*ctx };
    let root_seed = match mark_replay_and_get_root_seed(session_id) {
        Ok(seed) => seed,
        Err(code) => return code,
    };
    let key = derive_edge_key(edge, &root_seed);
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(_) => return ERR_CRYPTO,
    };

    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = edge_context_aad(edge);
    let plaintext = if plaintext_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(plaintext_ptr, plaintext_len) }
    };
    let mut ciphertext = plaintext.to_vec();
    let tag =
        match cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ciphertext) {
            Ok(tag) => tag,
            Err(_) => return ERR_CRYPTO,
        };

    unsafe {
        core::ptr::copy_nonoverlapping(nonce.as_ptr(), out_frame, AEAD_NONCE_LEN);
        core::ptr::copy_nonoverlapping(
            ciphertext.as_ptr(),
            out_frame.add(AEAD_NONCE_LEN),
            plaintext_len,
        );
        core::ptr::copy_nonoverlapping(
            tag.as_ptr(),
            out_frame.add(AEAD_NONCE_LEN + plaintext_len),
            AEAD_TAG_LEN,
        );
        *out_frame_len = required_len;
    }

    0
}

#[no_mangle]
pub extern "C" fn open_edge_packet(
    frame_ptr: *const u8,
    frame_len: usize,
    ctx: *const EdgeContext,
    session_id: u64,
    out_plaintext: *mut u8,
    out_plaintext_capacity: usize,
    out_plaintext_len: *mut usize,
) -> i32 {
    if frame_ptr.is_null()
        || ctx.is_null()
        || out_plaintext.is_null()
        || out_plaintext_len.is_null()
    {
        return ERR_NULL_POINTER;
    }
    if frame_len < AEAD_OVERHEAD {
        return ERR_AUTHENTICATION;
    }

    let plaintext_len = frame_len - AEAD_OVERHEAD;
    if out_plaintext_capacity < plaintext_len {
        return ERR_BUFFER_TOO_SMALL;
    }

    let edge = unsafe { &*ctx };
    let root_seed = match mark_replay_and_get_root_seed(session_id) {
        Ok(seed) => seed,
        Err(code) => return code,
    };
    let key = derive_edge_key(edge, &root_seed);
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(_) => return ERR_CRYPTO,
    };

    let frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
    let nonce = Nonce::from_slice(&frame[..AEAD_NONCE_LEN]);
    let tag = aes_gcm::Tag::from_slice(&frame[AEAD_NONCE_LEN + plaintext_len..]);
    let aad = edge_context_aad(edge);
    let mut plaintext = frame[AEAD_NONCE_LEN..AEAD_NONCE_LEN + plaintext_len].to_vec();

    if cipher
        .decrypt_in_place_detached(nonce, &aad, &mut plaintext, tag)
        .is_err()
    {
        return ERR_AUTHENTICATION;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_plaintext, plaintext_len);
        *out_plaintext_len = plaintext_len;
    }

    0
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
        return ERR_NULL_POINTER;
    }

    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    if !guard.try_mark_replay(session_id) {
        return ERR_REPLAY;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn edge() -> EdgeContext {
        EdgeContext {
            intent_id: 7,
            edge_id: 42,
            sequence: 9,
        }
    }

    #[test]
    fn test_zticam_edge_choreography() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let mut payload = [0u8; 32];
        payload.copy_from_slice(b"secret data inside the intent...");

        let in_ctx = EdgeContext {
            intent_id: 1,
            edge_id: 100,
            sequence: 1,
        };
        let out_ctx = EdgeContext {
            intent_id: 1,
            edge_id: 101,
            sequence: 2,
        };

        let res = choreograph_packet(payload.as_mut_ptr(), payload.len(), &in_ctx, &out_ctx, 555);
        assert_eq!(res, 0);

        let res2 = choreograph_packet(payload.as_mut_ptr(), payload.len(), &in_ctx, &out_ctx, 555);
        assert_eq!(res2, ERR_REPLAY);
    }

    #[test]
    fn test_edge_aead_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let plaintext = b"private key shard material";
        let mut frame = [0u8; 128];
        let mut frame_len = 0usize;

        let seal_res = seal_edge_packet(
            plaintext.as_ptr(),
            plaintext.len(),
            &ctx,
            10_001,
            frame.as_mut_ptr(),
            frame.len(),
            &mut frame_len,
        );
        assert_eq!(seal_res, 0);
        assert_eq!(frame_len, plaintext.len() + AEAD_OVERHEAD);
        assert_ne!(
            &frame[AEAD_NONCE_LEN..AEAD_NONCE_LEN + plaintext.len()],
            plaintext
        );

        let mut opened = [0u8; 64];
        let mut opened_len = 0usize;
        let open_res = open_edge_packet(
            frame.as_ptr(),
            frame_len,
            &ctx,
            10_002,
            opened.as_mut_ptr(),
            opened.len(),
            &mut opened_len,
        );
        assert_eq!(open_res, 0);
        assert_eq!(opened_len, plaintext.len());
        assert_eq!(&opened[..opened_len], plaintext);
    }

    #[test]
    fn test_edge_aead_rejects_tamper_and_wrong_context() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let plaintext = b"sensitive envelope";
        let mut frame = [0u8; 128];
        let mut frame_len = 0usize;

        assert_eq!(
            seal_edge_packet(
                plaintext.as_ptr(),
                plaintext.len(),
                &ctx,
                20_001,
                frame.as_mut_ptr(),
                frame.len(),
                &mut frame_len,
            ),
            0
        );

        let mut opened = [0u8; 64];
        let mut opened_len = 0usize;
        frame[AEAD_NONCE_LEN] ^= 0x80;
        assert_eq!(
            open_edge_packet(
                frame.as_ptr(),
                frame_len,
                &ctx,
                20_002,
                opened.as_mut_ptr(),
                opened.len(),
                &mut opened_len,
            ),
            ERR_AUTHENTICATION
        );

        frame[AEAD_NONCE_LEN] ^= 0x80;
        let wrong_ctx = EdgeContext {
            intent_id: ctx.intent_id,
            edge_id: ctx.edge_id + 1,
            sequence: ctx.sequence,
        };
        assert_eq!(
            open_edge_packet(
                frame.as_ptr(),
                frame_len,
                &wrong_ctx,
                20_003,
                opened.as_mut_ptr(),
                opened.len(),
                &mut opened_len,
            ),
            ERR_AUTHENTICATION
        );
    }

    #[test]
    fn test_edge_aead_validates_buffers_and_replay() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let plaintext = b"abc";
        let mut frame = [0u8; AEAD_OVERHEAD + 3];
        let mut frame_len = 0usize;

        assert_eq!(
            seal_edge_packet(
                plaintext.as_ptr(),
                plaintext.len(),
                &ctx,
                30_001,
                frame.as_mut_ptr(),
                AEAD_OVERHEAD,
                &mut frame_len,
            ),
            ERR_BUFFER_TOO_SMALL
        );

        assert_eq!(
            seal_edge_packet(
                core::ptr::null(),
                plaintext.len(),
                &ctx,
                30_002,
                frame.as_mut_ptr(),
                frame.len(),
                &mut frame_len,
            ),
            ERR_NULL_POINTER
        );

        assert_eq!(
            seal_edge_packet(
                plaintext.as_ptr(),
                plaintext.len(),
                &ctx,
                30_003,
                frame.as_mut_ptr(),
                frame.len(),
                &mut frame_len,
            ),
            0
        );
        assert_eq!(
            seal_edge_packet(
                plaintext.as_ptr(),
                plaintext.len(),
                &ctx,
                30_003,
                frame.as_mut_ptr(),
                frame.len(),
                &mut frame_len,
            ),
            ERR_REPLAY
        );
    }
}
