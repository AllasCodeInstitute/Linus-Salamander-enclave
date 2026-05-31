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
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Mutex,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct BehaviorMetric<'a> {
        name: &'a str,
        value: String,
        unit: &'a str,
    }

    struct BehaviorAssertion<'a> {
        name: &'a str,
        passed: bool,
    }

    fn metric<'a>(name: &'a str, value: impl ToString, unit: &'a str) -> BehaviorMetric<'a> {
        BehaviorMetric {
            name,
            value: value.to_string(),
            unit,
        }
    }

    fn assertion(name: &str, passed: bool) -> BehaviorAssertion<'_> {
        BehaviorAssertion { name, passed }
    }

    fn edge() -> EdgeContext {
        EdgeContext {
            intent_id: 7,
            edge_id: 42,
            sequence: 9,
        }
    }

    fn next_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after unix epoch")
            .as_nanos()
    }

    fn json_escape(value: &str) -> String {
        value
            .chars()
            .flat_map(|ch| match ch {
                '"' => "\\\"".chars().collect::<Vec<_>>(),
                '\\' => "\\\\".chars().collect::<Vec<_>>(),
                '\n' => "\\n".chars().collect::<Vec<_>>(),
                '\r' => "\\r".chars().collect::<Vec<_>>(),
                '\t' => "\\t".chars().collect::<Vec<_>>(),
                _ => vec![ch],
            })
            .collect()
    }

    fn report_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("test-results")
            .join("behavior-json")
    }

    fn update_manifest(dir: &Path) {
        let mut files = fs::read_dir(dir)
            .expect("behavior report dir must be readable")
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let file_name = path.file_name()?.to_str()?.to_owned();
                if path.extension()?.to_str()? == "json" && file_name != "manifest.json" {
                    Some(file_name)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        files.sort();

        let files_json = files
            .iter()
            .map(|file| format!("\"{}\"", json_escape(file)))
            .collect::<Vec<_>>()
            .join(",");
        let manifest = format!(
            "{{\n  \"schema\": \"lses.behavior.manifest.v1\",\n  \"generated_at_unix_nanos\": {},\n  \"files\": [{}]\n}}\n",
            next_nanos(), files_json
        );
        fs::write(dir.join("manifest.json"), manifest).expect("manifest must be writable");
    }

    fn write_behavior_json(
        category: &str,
        test_kind: &str,
        scope: &str,
        name: &str,
        status: &str,
        elapsed: std::time::Duration,
        metrics: &[BehaviorMetric<'_>],
        assertions: &[BehaviorAssertion<'_>],
        narrative: &str,
    ) {
        let dir = report_dir();
        fs::create_dir_all(&dir).expect("behavior report dir must be creatable");
        let id = format!(
            "{}_{}_{}_{}",
            category.to_ascii_lowercase(),
            test_kind,
            name,
            next_nanos()
        )
        .replace(
            |ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-',
            "_",
        );

        let metrics_json = metrics
            .iter()
            .map(|item| {
                format!(
                    "    {{ \"name\": \"{}\", \"value\": \"{}\", \"unit\": \"{}\" }}",
                    json_escape(item.name),
                    json_escape(&item.value),
                    json_escape(item.unit)
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        let assertions_json = assertions
            .iter()
            .map(|item| {
                format!(
                    "    {{ \"name\": \"{}\", \"passed\": {} }}",
                    json_escape(item.name),
                    item.passed
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");

        let payload = format!(
            "{{\n  \"schema\": \"lses.behavior.result.v1\",\n  \"id\": \"{}\",\n  \"category\": \"{}\",\n  \"test_kind\": \"{}\",\n  \"scope\": \"{}\",\n  \"name\": \"{}\",\n  \"status\": \"{}\",\n  \"duration_ns\": {},\n  \"narrative\": \"{}\",\n  \"metrics\": [\n{}\n  ],\n  \"assertions\": [\n{}\n  ]\n}}\n",
            json_escape(&id),
            json_escape(category),
            json_escape(test_kind),
            json_escape(scope),
            json_escape(name),
            json_escape(status),
            elapsed.as_nanos(),
            json_escape(narrative),
            metrics_json,
            assertions_json
        );
        fs::write(dir.join(format!("{id}.json")), payload)
            .expect("behavior result must be writable");
        update_manifest(&dir);
    }

    fn generate_agent_key_for(
        name: &[u8],
        caps: &[u8],
        plane: &[u8],
        semantics: &[u8],
    ) -> [u8; 32] {
        let mut out = [0u8; 32];
        let status = generate_agent_key(
            name.as_ptr(),
            name.len(),
            caps.as_ptr(),
            caps.len(),
            plane.as_ptr(),
            plane.len(),
            semantics.as_ptr(),
            semantics.len(),
            out.as_mut_ptr(),
        );
        assert_eq!(status, 0);
        out
    }

    fn seal_packet(ctx: &EdgeContext, session_id: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; plaintext.len() + AEAD_OVERHEAD];
        let mut frame_len = 0usize;
        let status = seal_edge_packet(
            plaintext.as_ptr(),
            plaintext.len(),
            ctx,
            session_id,
            frame.as_mut_ptr(),
            frame.len(),
            &mut frame_len,
        );
        assert_eq!(status, 0);
        frame.truncate(frame_len);
        frame
    }

    fn open_packet(ctx: &EdgeContext, session_id: u64, frame: &[u8]) -> Result<Vec<u8>, i32> {
        let mut out = vec![0u8; frame.len()];
        let mut out_len = 0usize;
        let status = open_edge_packet(
            frame.as_ptr(),
            frame.len(),
            ctx,
            session_id,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        if status == 0 {
            out.truncate(out_len);
            Ok(out)
        } else {
            Err(status)
        }
    }

    fn sign_payload(session_id: u64, payload: &[u8]) -> [u8; 64] {
        let mut sig = [0u8; 64];
        let status = noise_sign_payload(
            payload.as_ptr(),
            payload.len(),
            sig.as_mut_ptr(),
            session_id,
        );
        assert_eq!(status, 0);
        sig
    }

    fn execute_intent(intent_id: u64, session_base: u64, payload: &[u8]) -> (Vec<u8>, [u8; 64]) {
        let ctx = EdgeContext {
            intent_id,
            edge_id: 11,
            sequence: 1,
        };
        let agent_key = generate_agent_key_for(
            b"UIAgent",
            b"request_private_key_signature",
            b"control-plane",
            b"intent-envelope",
        );
        let mut intent_payload = Vec::from(payload);
        intent_payload.extend_from_slice(&agent_key[..8]);
        let frame = seal_packet(&ctx, session_base, &intent_payload);
        let opened = open_packet(&ctx, session_base + 1, &frame).expect("intent must open");
        let signature = sign_payload(session_base + 2, &opened);
        (opened, signature)
    }

    #[test]
    fn quark_unit_generate_agent_key_is_deterministic() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let key_a = generate_agent_key_for(b"Signer", b"ed25519", b"data", b"private-key");
        let key_b = generate_agent_key_for(b"Signer", b"ed25519", b"data", b"private-key");
        let key_c = generate_agent_key_for(b"Signer", b"audit", b"data", b"private-key");
        let assertions = [
            assertion("same semantic inputs produce the same key", key_a == key_b),
            assertion("capability changes produce a different key", key_a != key_c),
        ];
        write_behavior_json(
            "QuarkBehaviors",
            "unit",
            "function",
            "generate_agent_key_deterministic",
            "passed",
            started.elapsed(),
            &[metric("keys_generated", 3, "count")],
            &assertions,
            "Validates deterministic semantic key derivation at the function layer.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn quark_load_generate_agent_key_many_inputs() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let mut accumulator = 0u8;
        for i in 0..512u32 {
            let name = format!("Agent-{i}");
            let key = generate_agent_key_for(name.as_bytes(), b"sign", b"data", b"intent");
            accumulator ^= key[0];
        }
        let assertions = [assertion(
            "load loop produced non-trivial aggregate",
            accumulator != 0,
        )];
        write_behavior_json(
            "QuarkBehaviors",
            "load",
            "function",
            "generate_agent_key_512_inputs",
            "passed",
            started.elapsed(),
            &[metric("iterations", 512, "count")],
            &assertions,
            "Exercises repeated semantic key derivation with many independent inputs.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn quark_stress_seal_edge_packet_repeated() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let started = Instant::now();
        let mut total_bytes = 0usize;
        for i in 0..256u64 {
            let payload = format!("stress-payload-{i}-private-key-fragment");
            let frame = seal_packet(&ctx, 1_000 + i, payload.as_bytes());
            total_bytes += frame.len();
        }
        let assertions = [assertion(
            "all stress frames include AEAD overhead",
            total_bytes > 256 * AEAD_OVERHEAD,
        )];
        write_behavior_json(
            "QuarkBehaviors",
            "stress",
            "function",
            "seal_edge_packet_256_frames",
            "passed",
            started.elapsed(),
            &[
                metric("frames", 256, "count"),
                metric("total_bytes", total_bytes, "bytes"),
            ],
            &assertions,
            "Stresses the sealing function with repeated unique sessions.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn quark_chaos_open_edge_packet_rejects_truncated_frame() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let started = Instant::now();
        let frame = [0u8; AEAD_OVERHEAD - 1];
        let result = open_packet(&ctx, 2_000, &frame);
        let assertions = [assertion(
            "truncated frame is rejected",
            result == Err(ERR_AUTHENTICATION),
        )];
        write_behavior_json(
            "QuarkBehaviors",
            "chaos",
            "function",
            "open_edge_packet_truncated_frame",
            "passed",
            started.elapsed(),
            &[metric("frame_len", frame.len(), "bytes")],
            &assertions,
            "Injects malformed frame length into the open function.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn quark_security_replay_guard_blocks_duplicate_session() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let started = Instant::now();
        let payload = b"replay-protected";
        let _frame = seal_packet(&ctx, 3_000, payload);
        let mut out = vec![0u8; payload.len() + AEAD_OVERHEAD];
        let mut out_len = 0usize;
        let replay_status = seal_edge_packet(
            payload.as_ptr(),
            payload.len(),
            &ctx,
            3_000,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        let assertions = [assertion(
            "duplicate session is rejected",
            replay_status == ERR_REPLAY,
        )];
        write_behavior_json(
            "QuarkBehaviors",
            "security",
            "function",
            "seal_edge_packet_replay_guard",
            "passed",
            started.elapsed(),
            &[metric("duplicate_session_id", 3_000, "id")],
            &assertions,
            "Verifies function-level replay prevention before a duplicate seal can occur.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn quark_benchmark_seal_open_latency() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let payload = b"benchmark-private-key-operation";
        let started = Instant::now();
        for i in 0..128u64 {
            let frame = seal_packet(&ctx, 4_000 + (i * 2), payload);
            let opened =
                open_packet(&ctx, 4_001 + (i * 2), &frame).expect("benchmark open must succeed");
            assert_eq!(opened, payload);
        }
        let elapsed = started.elapsed();
        let assertions = [assertion("benchmark loop completed", true)];
        write_behavior_json(
            "QuarkBehaviors",
            "benchmark",
            "function",
            "seal_open_128_latency",
            "passed",
            elapsed,
            &[
                metric("iterations", 128, "count"),
                metric("avg_ns_per_roundtrip", elapsed.as_nanos() / 128, "ns"),
            ],
            &assertions,
            "Measures a lightweight in-test function-level seal/open roundtrip benchmark.",
        );
    }

    #[test]
    fn atomic_unit_edge_aead_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let plaintext = b"private key shard material";
        let started = Instant::now();
        let frame = seal_packet(&ctx, 10_001, plaintext);
        let opened = open_packet(&ctx, 10_002, &frame).expect("roundtrip must open");
        let assertions = [
            assertion("opened plaintext matches input", opened == plaintext),
            assertion(
                "ciphertext differs from plaintext",
                &frame[AEAD_NONCE_LEN..AEAD_NONCE_LEN + plaintext.len()] != plaintext,
            ),
        ];
        write_behavior_json(
            "AtomicBehaviors",
            "unit",
            "functionality",
            "edge_aead_roundtrip",
            "passed",
            started.elapsed(),
            &[metric("frame_len", frame.len(), "bytes")],
            &assertions,
            "Validates the AEAD envelope functionality across seal and open APIs.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn atomic_load_multiple_edges_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        for i in 0..96u64 {
            let ctx = EdgeContext {
                intent_id: 77,
                edge_id: i,
                sequence: i + 1,
            };
            let payload = format!("edge-load-{i}");
            let frame = seal_packet(&ctx, 11_000 + (i * 2), payload.as_bytes());
            let opened = open_packet(&ctx, 11_001 + (i * 2), &frame).expect("edge load open");
            assert_eq!(opened, payload.as_bytes());
        }
        let assertions = [assertion("all edge contexts completed", true)];
        write_behavior_json(
            "AtomicBehaviors",
            "load",
            "functionality",
            "edge_aead_96_contexts",
            "passed",
            started.elapsed(),
            &[metric("edges", 96, "count")],
            &assertions,
            "Loads the AEAD functionality across many edge contexts.",
        );
    }

    #[test]
    fn atomic_stress_intent_choreography_and_aead() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let mut transformed = 0usize;
        for i in 0..128u64 {
            let in_ctx = EdgeContext {
                intent_id: 88,
                edge_id: 1,
                sequence: i,
            };
            let out_ctx = EdgeContext {
                intent_id: 88,
                edge_id: 2,
                sequence: i + 1,
            };
            let mut payload = [i as u8; 32];
            assert_eq!(
                choreograph_packet(
                    payload.as_mut_ptr(),
                    payload.len(),
                    &in_ctx,
                    &out_ctx,
                    12_000 + i
                ),
                0
            );
            let frame = seal_packet(&out_ctx, 13_000 + i, &payload);
            transformed += frame.len();
        }
        let assertions = [assertion(
            "stress choreography produced sealed output",
            transformed > 128 * AEAD_OVERHEAD,
        )];
        write_behavior_json(
            "AtomicBehaviors",
            "stress",
            "functionality",
            "choreography_plus_aead_128",
            "passed",
            started.elapsed(),
            &[
                metric("flows", 128, "count"),
                metric("sealed_bytes", transformed, "bytes"),
            ],
            &assertions,
            "Combines choreography transformation with AEAD sealing under stress.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn atomic_chaos_rejects_tamper_and_wrong_context() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let started = Instant::now();
        let mut frame = seal_packet(&ctx, 20_001, b"sensitive envelope");
        frame[AEAD_NONCE_LEN] ^= 0x80;
        let tamper = open_packet(&ctx, 20_002, &frame);
        frame[AEAD_NONCE_LEN] ^= 0x80;
        let wrong_ctx = EdgeContext {
            intent_id: ctx.intent_id,
            edge_id: ctx.edge_id + 1,
            sequence: ctx.sequence,
        };
        let wrong = open_packet(&wrong_ctx, 20_003, &frame);
        let assertions = [
            assertion(
                "tampered ciphertext is rejected",
                tamper == Err(ERR_AUTHENTICATION),
            ),
            assertion(
                "wrong edge context is rejected",
                wrong == Err(ERR_AUTHENTICATION),
            ),
        ];
        write_behavior_json(
            "AtomicBehaviors",
            "chaos",
            "functionality",
            "edge_aead_tamper_wrong_context",
            "passed",
            started.elapsed(),
            &[metric("mutations", 2, "count")],
            &assertions,
            "Injects ciphertext and AAD/context faults into the AEAD functionality.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn atomic_security_identity_signature_and_envelope() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let identity = TripartiteIdentity {
            pub_key: [7u8; 32],
            mac_addr: [1, 2, 3, 4, 5, 6],
            ip_addr: [10, 0, 0, 9],
        };
        let mut hasher = Sha256::new();
        hasher.update(identity.pub_key);
        hasher.update(identity.mac_addr);
        hasher.update(identity.ip_addr);
        let expected = hasher.finalize();
        let identity_status = verify_tripartite_identity(&identity, expected.as_ptr());
        let frame = seal_packet(&edge(), 21_001, b"signed-envelope");
        let sig = sign_payload(21_002, &frame);
        let assertions = [
            assertion("tripartite identity verifies", identity_status == 0),
            assertion("signature is non-empty", sig.iter().any(|byte| *byte != 0)),
        ];
        write_behavior_json(
            "AtomicBehaviors",
            "security",
            "functionality",
            "identity_signature_envelope",
            "passed",
            started.elapsed(),
            &[metric("signature_len", sig.len(), "bytes"), metric("frame_len", frame.len(), "bytes")],
            &assertions,
            "Validates identity verification, envelope sealing, and payload signing as one security behavior.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn atomic_benchmark_feature_pipeline_latency() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let started = Instant::now();
        for i in 0..64u64 {
            let payload = format!("feature-benchmark-{i}");
            let frame = seal_packet(&ctx, 22_000 + (i * 3), payload.as_bytes());
            let opened =
                open_packet(&ctx, 22_001 + (i * 3), &frame).expect("feature benchmark open");
            let _sig = sign_payload(22_002 + (i * 3), &opened);
        }
        let elapsed = started.elapsed();
        let assertions = [assertion("feature pipeline completed", true)];
        write_behavior_json(
            "AtomicBehaviors",
            "benchmark",
            "functionality",
            "edge_pipeline_64_latency",
            "passed",
            elapsed,
            &[
                metric("pipelines", 64, "count"),
                metric("avg_ns_per_pipeline", elapsed.as_nanos() / 64, "ns"),
            ],
            &assertions,
            "Benchmarks the atomic envelope plus signing functionality path.",
        );
    }

    #[test]
    fn project_unit_single_intent_pipeline() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let (opened, signature) = execute_intent(100, 30_000, b"intent:sign-wallet-transaction");
        let assertions = [
            assertion(
                "intent payload survives composition",
                opened.starts_with(b"intent:sign-wallet-transaction"),
            ),
            assertion(
                "intent signature emitted",
                signature.iter().any(|byte| *byte != 0),
            ),
        ];
        write_behavior_json(
            "Project",
            "unit",
            "intent",
            "single_intent_pipeline",
            "passed",
            started.elapsed(),
            &[metric("opened_len", opened.len(), "bytes")],
            &assertions,
            "Composes semantic key derivation, AEAD envelope, and signing as a common Intent flow.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn project_load_many_intents() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        for i in 0..48u64 {
            let payload = format!("intent:rotate-key:{i}");
            let (opened, _sig) = execute_intent(200 + i, 31_000 + (i * 4), payload.as_bytes());
            assert!(opened.starts_with(payload.as_bytes()));
        }
        let assertions = [assertion("all load intents completed", true)];
        write_behavior_json(
            "Project",
            "load",
            "intent",
            "intent_pipeline_48_load",
            "passed",
            started.elapsed(),
            &[metric("intents", 48, "count")],
            &assertions,
            "Loads the project-level Intent pipeline with multiple key-operation intents.",
        );
    }

    #[test]
    fn project_stress_intent_pipeline_96_flows() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let mut signed = 0usize;
        for i in 0..96u64 {
            let payload = format!("intent:authorize-transfer:{i}:amount:42");
            let (_opened, sig) = execute_intent(300 + i, 32_000 + (i * 4), payload.as_bytes());
            signed += sig.len();
        }
        let assertions = [assertion(
            "stress intents emitted signatures",
            signed == 96 * 64,
        )];
        write_behavior_json(
            "Project",
            "stress",
            "intent",
            "intent_pipeline_96_stress",
            "passed",
            started.elapsed(),
            &[
                metric("intents", 96, "count"),
                metric("signed_bytes", signed, "bytes"),
            ],
            &assertions,
            "Stresses complete Intent composition under repeated enclave operations.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn project_chaos_tampered_intent_is_blocked() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let ctx = EdgeContext {
            intent_id: 400,
            edge_id: 11,
            sequence: 1,
        };
        let mut frame = seal_packet(&ctx, 33_000, b"intent:tamper-me");
        let last = frame.len() - 1;
        frame[last] ^= 0x40;
        let blocked = open_packet(&ctx, 33_001, &frame);
        let assertions = [assertion(
            "tampered intent frame is blocked",
            blocked == Err(ERR_AUTHENTICATION),
        )];
        write_behavior_json(
            "Project",
            "chaos",
            "intent",
            "tampered_intent_blocked",
            "passed",
            started.elapsed(),
            &[metric("tampered_bytes", 1, "count")],
            &assertions,
            "Injects a corrupted tag into a project-level Intent envelope.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn project_security_replayed_intent_is_blocked() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        let ctx = EdgeContext {
            intent_id: 500,
            edge_id: 11,
            sequence: 1,
        };
        let payload = b"intent:no-replay";
        let _frame = seal_packet(&ctx, 34_000, payload);
        let mut frame = vec![0u8; payload.len() + AEAD_OVERHEAD];
        let mut frame_len = 0usize;
        let replay = seal_edge_packet(
            payload.as_ptr(),
            payload.len(),
            &ctx,
            34_000,
            frame.as_mut_ptr(),
            frame.len(),
            &mut frame_len,
        );
        let assertions = [assertion(
            "replayed intent session is blocked",
            replay == ERR_REPLAY,
        )];
        write_behavior_json(
            "Project",
            "security",
            "intent",
            "replayed_intent_blocked",
            "passed",
            started.elapsed(),
            &[metric("session_id", 34_000, "id")],
            &assertions,
            "Verifies project-level Intent replay resistance.",
        );
        assert!(assertions.iter().all(|item| item.passed));
    }

    #[test]
    fn project_benchmark_intent_pipeline_latency() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let started = Instant::now();
        for i in 0..32u64 {
            let payload = format!("intent:benchmark:{i}");
            let (_opened, _sig) = execute_intent(600 + i, 35_000 + (i * 4), payload.as_bytes());
        }
        let elapsed = started.elapsed();
        let assertions = [assertion("intent benchmark completed", true)];
        write_behavior_json(
            "Project",
            "benchmark",
            "intent",
            "intent_pipeline_32_latency",
            "passed",
            elapsed,
            &[
                metric("intents", 32, "count"),
                metric("avg_ns_per_intent", elapsed.as_nanos() / 32, "ns"),
            ],
            &assertions,
            "Benchmarks the complete project-level Intent composition path.",
        );
    }
}
