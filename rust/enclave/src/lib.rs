use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
// ed25519_dalek::{VerifyingKey, Signature} are accessed via fully-qualified paths
// in the quarkbehavior files to keep each behavior self-documenting.
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

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

include!("../../semantic-behaviors-types/quarkbehaviors/state/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/init_pqc_session/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/verify_pqc_handshake/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/init_enclave_keys/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/generate_agent_key/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/derive_edge_key/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/edge_context_aad/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/seal_edge_packet/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/open_edge_packet/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/choreograph_packet/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/noise_sign_payload/proccess.rs");

include!("../../semantic-behaviors-types/quarkbehaviors/noise_sign_scoped_payload/proccess.rs");

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
    fn atomic_unit_choreograph_packet_reencrypts_aead_frame() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let in_ctx = EdgeContext {
            intent_id: 70,
            edge_id: 1,
            sequence: 1,
        };
        let out_ctx = EdgeContext {
            intent_id: 70,
            edge_id: 2,
            sequence: 2,
        };
        let plaintext = b"hop-private-key-material";
        let mut frame = seal_packet(&in_ctx, 12_000, plaintext);

        let status = choreograph_packet(
            frame.as_mut_ptr(),
            frame.len(),
            &in_ctx,
            &out_ctx,
            12_001,
        );

        assert_eq!(status, 0);
        assert_eq!(
            open_packet(&in_ctx, 12_002, &frame),
            Err(ERR_AUTHENTICATION),
            "re-choreographed frame must no longer authenticate under the input edge"
        );
        assert_eq!(
            open_packet(&out_ctx, 12_003, &frame).expect("output edge must open frame"),
            plaintext
        );
    }

    #[test]
    fn atomic_security_choreograph_packet_rejects_raw_payload() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let in_ctx = EdgeContext {
            intent_id: 71,
            edge_id: 1,
            sequence: 1,
        };
        let out_ctx = EdgeContext {
            intent_id: 71,
            edge_id: 2,
            sequence: 2,
        };
        let mut raw_payload = *b"not-an-aead-frame";

        let status = choreograph_packet(
            raw_payload.as_mut_ptr(),
            raw_payload.len(),
            &in_ctx,
            &out_ctx,
            12_010,
        );

        assert_eq!(status, ERR_AUTHENTICATION);
    }

    #[test]
    fn ffi_unit_error_contracts_reject_null_and_small_buffers() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let ctx = edge();
        let payload = b"ffi-error-contract";
        let mut frame = [0u8; 64];
        let mut frame_len = 0usize;
        let mut out = [0u8; 4];
        let mut out_len = 0usize;
        let mut sig = [0u8; 64];

        assert_eq!(
            seal_edge_packet(
                core::ptr::null(),
                payload.len(),
                &ctx,
                60_000,
                frame.as_mut_ptr(),
                frame.len(),
                &mut frame_len,
            ),
            ERR_NULL_POINTER
        );
        assert_eq!(
            seal_edge_packet(
                payload.as_ptr(),
                payload.len(),
                &ctx,
                60_001,
                frame.as_mut_ptr(),
                AEAD_OVERHEAD,
                &mut frame_len,
            ),
            ERR_BUFFER_TOO_SMALL
        );

        let frame_vec = seal_packet(&ctx, 60_002, payload);
        assert_eq!(
            open_edge_packet(
                frame_vec.as_ptr(),
                frame_vec.len(),
                &ctx,
                60_003,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            ERR_BUFFER_TOO_SMALL
        );
        assert_eq!(
            open_edge_packet(
                core::ptr::null(),
                frame_vec.len(),
                &ctx,
                60_004,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            ),
            ERR_NULL_POINTER
        );
        assert_eq!(
            noise_sign_payload(core::ptr::null(), payload.len(), sig.as_mut_ptr(), 60_005),
            ERR_NULL_POINTER
        );
        assert_eq!(
            choreograph_packet(core::ptr::null_mut(), 0, &ctx, &ctx, 60_006),
            ERR_NULL_POINTER
        );
    }

    #[test]
    fn ffi_security_choreograph_packet_replay_is_rejected() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let in_ctx = EdgeContext {
            intent_id: 72,
            edge_id: 1,
            sequence: 1,
        };
        let out_ctx = EdgeContext {
            intent_id: 72,
            edge_id: 2,
            sequence: 2,
        };
        let payload = b"ffi replay payload";
        let mut first_frame = seal_packet(&in_ctx, 61_000, payload);
        let mut replay_frame = seal_packet(&in_ctx, 61_001, payload);

        assert_eq!(
            choreograph_packet(
                first_frame.as_mut_ptr(),
                first_frame.len(),
                &in_ctx,
                &out_ctx,
                61_002,
            ),
            0
        );
        assert_eq!(
            choreograph_packet(
                replay_frame.as_mut_ptr(),
                replay_frame.len(),
                &in_ctx,
                &out_ctx,
                61_002,
            ),
            ERR_REPLAY
        );
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
            let payload = [i as u8; 32];
            let mut frame = seal_packet(&in_ctx, 12_000 + (i * 3), &payload);
            assert_eq!(
                choreograph_packet(
                    frame.as_mut_ptr(),
                    frame.len(),
                    &in_ctx,
                    &out_ctx,
                    12_001 + (i * 3),
                ),
                0
            );
            assert_eq!(
                open_packet(&out_ctx, 12_002 + (i * 3), &frame)
                    .expect("choreographed stress frame must open"),
                payload
            );
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

#[cfg(test)]
mod modular_quarkbehavior_tests {
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Mutex,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    static MODULAR_TEST_LOCK: Mutex<()> = Mutex::new(());

    mod state_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/state/tests.load.rs");
    }
    mod state_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/state/tests.stress.rs");
    }
    mod state_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/state/tests.chaos.rs");
    }
    mod state_security {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/state/tests.security.rs");
    }
    mod state_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/state/benchmark.rs");
    }
    mod init_pqc_session_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_pqc_session/tests.load.rs");
    }
    mod init_pqc_session_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_pqc_session/tests.stress.rs");
    }
    mod init_pqc_session_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_pqc_session/tests.chaos.rs");
    }
    mod init_pqc_session_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/init_pqc_session/tests.security.rs"
        );
    }
    mod init_pqc_session_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_pqc_session/benchmark.rs");
    }
    mod verify_pqc_handshake_load {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/verify_pqc_handshake/tests.load.rs"
        );
    }
    mod verify_pqc_handshake_stress {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/verify_pqc_handshake/tests.stress.rs"
        );
    }
    mod verify_pqc_handshake_chaos {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/verify_pqc_handshake/tests.chaos.rs"
        );
    }
    mod verify_pqc_handshake_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/verify_pqc_handshake/tests.security.rs"
        );
    }
    mod verify_pqc_handshake_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/verify_pqc_handshake/benchmark.rs");
    }
    mod init_enclave_keys_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_enclave_keys/tests.load.rs");
    }
    mod init_enclave_keys_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_enclave_keys/tests.stress.rs");
    }
    mod init_enclave_keys_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_enclave_keys/tests.chaos.rs");
    }
    mod init_enclave_keys_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/init_enclave_keys/tests.security.rs"
        );
    }
    mod init_enclave_keys_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/init_enclave_keys/benchmark.rs");
    }
    mod generate_agent_key_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/generate_agent_key/tests.load.rs");
    }
    mod generate_agent_key_stress {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/generate_agent_key/tests.stress.rs"
        );
    }
    mod generate_agent_key_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/generate_agent_key/tests.chaos.rs");
    }
    mod generate_agent_key_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/generate_agent_key/tests.security.rs"
        );
    }
    mod generate_agent_key_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/generate_agent_key/benchmark.rs");
    }
    mod verify_tripartite_identity_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/tests.load.rs");
    }
    mod verify_tripartite_identity_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/tests.stress.rs");
    }
    mod verify_tripartite_identity_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/tests.chaos.rs");
    }
    mod verify_tripartite_identity_security {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/tests.security.rs");
    }
    mod verify_tripartite_identity_benchmark {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/verify_tripartite_identity/benchmark.rs"
        );
    }
    mod derive_edge_key_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/derive_edge_key/tests.load.rs");
    }
    mod derive_edge_key_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/derive_edge_key/tests.stress.rs");
    }
    mod derive_edge_key_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/derive_edge_key/tests.chaos.rs");
    }
    mod derive_edge_key_security {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/derive_edge_key/tests.security.rs");
    }
    mod derive_edge_key_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/derive_edge_key/benchmark.rs");
    }
    mod edge_context_aad_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/edge_context_aad/tests.load.rs");
    }
    mod edge_context_aad_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/edge_context_aad/tests.stress.rs");
    }
    mod edge_context_aad_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/edge_context_aad/tests.chaos.rs");
    }
    mod edge_context_aad_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/edge_context_aad/tests.security.rs"
        );
    }
    mod edge_context_aad_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/edge_context_aad/benchmark.rs");
    }
    mod mark_replay_and_get_root_seed_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/tests.load.rs");
    }
    mod mark_replay_and_get_root_seed_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/tests.stress.rs");
    }
    mod mark_replay_and_get_root_seed_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/tests.chaos.rs");
    }
    mod mark_replay_and_get_root_seed_security {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/tests.security.rs");
    }
    mod mark_replay_and_get_root_seed_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/mark_replay_and_get_root_seed/benchmark.rs");
    }
    mod seal_edge_packet_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/seal_edge_packet/tests.load.rs");
    }
    mod seal_edge_packet_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/seal_edge_packet/tests.stress.rs");
    }
    mod seal_edge_packet_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/seal_edge_packet/tests.chaos.rs");
    }
    mod seal_edge_packet_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/seal_edge_packet/tests.security.rs"
        );
    }
    mod seal_edge_packet_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/seal_edge_packet/benchmark.rs");
    }
    mod open_edge_packet_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/open_edge_packet/tests.load.rs");
    }
    mod open_edge_packet_stress {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/open_edge_packet/tests.stress.rs");
    }
    mod open_edge_packet_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/open_edge_packet/tests.chaos.rs");
    }
    mod open_edge_packet_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/open_edge_packet/tests.security.rs"
        );
    }
    mod open_edge_packet_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/open_edge_packet/benchmark.rs");
    }
    mod choreograph_packet_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/choreograph_packet/tests.load.rs");
    }
    mod choreograph_packet_stress {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/choreograph_packet/tests.stress.rs"
        );
    }
    mod choreograph_packet_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/choreograph_packet/tests.chaos.rs");
    }
    mod choreograph_packet_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/choreograph_packet/tests.security.rs"
        );
    }
    mod choreograph_packet_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/choreograph_packet/benchmark.rs");
    }
    mod noise_sign_payload_load {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/noise_sign_payload/tests.load.rs");
    }
    mod noise_sign_payload_stress {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/noise_sign_payload/tests.stress.rs"
        );
    }
    mod noise_sign_payload_chaos {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/noise_sign_payload/tests.chaos.rs");
    }
    mod noise_sign_payload_security {
        use super::*;
        include!(
            "../../semantic-behaviors-types/quarkbehaviors/noise_sign_payload/tests.security.rs"
        );
    }
    mod noise_sign_payload_benchmark {
        use super::*;
        include!("../../semantic-behaviors-types/quarkbehaviors/noise_sign_payload/benchmark.rs");
    }

    fn report_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("test-results")
            .join("semantic-quarkbehavior-json")
    }

    fn now_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be valid")
            .as_nanos()
    }

    fn escape_json(value: &str) -> String {
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

    fn rss_bytes() -> u64 {
        let Ok(status) = fs::read_to_string("/proc/self/status") else {
            return 0;
        };
        status
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:").and_then(|rest| {
                    rest.split_whitespace()
                        .next()
                        .and_then(|kb| kb.parse::<u64>().ok())
                        .map(|kb| kb * 1024)
                })
            })
            .unwrap_or(0)
    }

    fn cpu_seconds() -> f64 {
        let Ok(stat) = fs::read_to_string("/proc/self/stat") else {
            return 0.0;
        };
        let Some(end_comm) = stat.rfind(") ") else {
            return 0.0;
        };
        let fields = stat[end_comm + 2..].split_whitespace().collect::<Vec<_>>();
        let utime = fields
            .get(11)
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let stime = fields
            .get(12)
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        (utime + stime) / 100.0
    }

    fn update_manifest(dir: &Path) {
        let mut files = fs::read_dir(dir)
            .expect("semantic quarkbehavior report dir must be readable")
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
            .map(|file| format!("\"{}\"", escape_json(file)))
            .collect::<Vec<_>>()
            .join(",");
        let manifest = format!(
            "{{\n  \"schema\": \"lses.semantic.quarkbehavior.manifest.v1\",\n  \"generated_at_unix_nanos\": {},\n  \"files\": [{}]\n}}\n",
            now_nanos(), files_json
        );
        fs::write(dir.join("manifest.json"), manifest)
            .expect("semantic quarkbehavior manifest must be writable");
    }

    fn write_modular_report(
        function_name: &str,
        kind: &str,
        iterations: u64,
        wall_ns: u128,
        cpu_delta_seconds: f64,
        rss_start: u64,
        rss_end: u64,
        max_rss_bytes: u64,
        passed: bool,
    ) {
        let dir = report_dir();
        fs::create_dir_all(&dir).expect("semantic quarkbehavior report dir must be creatable");
        let id = format!("{}_{}_{}", function_name, kind, now_nanos());
        let exec_per_second = if wall_ns == 0 {
            0.0
        } else {
            (iterations as f64) / ((wall_ns as f64) / 1_000_000_000.0)
        };
        let cpu_per_execution = if iterations == 0 {
            0.0
        } else {
            cpu_delta_seconds / iterations as f64
        };
        let ram_delta = rss_end.saturating_sub(rss_start);
        let ram_per_execution = if iterations == 0 {
            0
        } else {
            ram_delta / iterations
        };
        let payload = format!(
            "{{\n  \"schema\": \"lses.semantic.quarkbehavior.result.v1\",\n  \"id\": \"{}\",\n  \"category\": \"QuarkBehaviors\",\n  \"function_name\": \"{}\",\n  \"test_kind\": \"{}\",\n  \"status\": \"{}\",\n  \"iterations\": {},\n  \"wall_ns\": {},\n  \"executions_per_second\": {:.6},\n  \"cpu_seconds_total\": {:.9},\n  \"cpu_seconds_per_execution\": {:.12},\n  \"ram_bytes_start\": {},\n  \"ram_bytes_end\": {},\n  \"ram_bytes_per_execution\": {},\n  \"ram_bytes_max\": {},\n  \"assertions\": [{{ \"name\": \"modular function behavior completed\", \"passed\": {} }}]\n}}\n",
            escape_json(&id),
            escape_json(function_name),
            escape_json(kind),
            if passed { "passed" } else { "failed" },
            iterations,
            wall_ns,
            exec_per_second,
            cpu_delta_seconds,
            cpu_per_execution,
            rss_start,
            rss_end,
            ram_per_execution,
            max_rss_bytes,
            passed
        );
        fs::write(dir.join(format!("{id}.json")), payload)
            .expect("semantic quarkbehavior result must be writable");
        update_manifest(&dir);
    }

    fn sample_edge() -> EdgeContext {
        EdgeContext {
            intent_id: 9,
            edge_id: 3,
            sequence: 1,
        }
    }

    fn session_seed(function_name: &str, iteration: u64) -> u64 {
        let hash = function_name.bytes().fold(0u64, |acc, byte| {
            acc.wrapping_mul(131).wrapping_add(byte as u64)
        });
        40_000 + ((hash + iteration * 7) % 20_000)
    }

    fn exercise_function(function_name: &str, iteration: u64) -> bool {
        match function_name {
            "state" => state().lock().is_ok(),
            "init_pqc_session" => {
                let mut out = [0u8; 1184];
                init_pqc_session(session_seed(function_name, iteration), out.as_mut_ptr()) == 0
                    && out[0] == 0xAA
            }
            "verify_pqc_handshake" => {
                let mut out = [0u8; 1184];
                let sid = session_seed(function_name, iteration);
                init_pqc_session(sid, out.as_mut_ptr()) == 0
                    && verify_pqc_handshake(sid, core::ptr::null()) == 0
            }
            "init_enclave_keys" => {
                init_enclave_keys();
                true
            }
            "generate_agent_key" => {
                let name = format!("agent-{iteration}");
                let mut out = [0u8; 32];
                generate_agent_key(
                    name.as_ptr(),
                    name.len(),
                    b"sign".as_ptr(),
                    4,
                    b"data".as_ptr(),
                    4,
                    b"intent".as_ptr(),
                    6,
                    out.as_mut_ptr(),
                ) == 0
                    && out.iter().any(|byte| *byte != 0)
            }
            "verify_tripartite_identity" => {
                let id = TripartiteIdentity {
                    pub_key: [iteration as u8; 32],
                    mac_addr: [1, 2, 3, 4, 5, 6],
                    ip_addr: [127, 0, 0, 1],
                };
                let mut hasher = Sha256::new();
                hasher.update(id.pub_key);
                hasher.update(id.mac_addr);
                hasher.update(id.ip_addr);
                let expected = hasher.finalize();
                verify_tripartite_identity(&id, expected.as_ptr()) == 0
            }
            "derive_edge_key" => derive_edge_key(&sample_edge(), &ROOT_SEED_DEFAULT)
                .iter()
                .any(|byte| *byte != 0),
            "edge_context_aad" => edge_context_aad(&sample_edge()).len() == 24,
            "mark_replay_and_get_root_seed" => {
                mark_replay_and_get_root_seed(session_seed(function_name, iteration)).is_ok()
            }
            "seal_edge_packet" => {
                let ctx = sample_edge();
                let payload = b"semantic seal payload";
                let mut frame = [0u8; 96];
                let mut frame_len = 0usize;
                seal_edge_packet(
                    payload.as_ptr(),
                    payload.len(),
                    &ctx,
                    session_seed(function_name, iteration),
                    frame.as_mut_ptr(),
                    frame.len(),
                    &mut frame_len,
                ) == 0
                    && frame_len == payload.len() + AEAD_OVERHEAD
            }
            "open_edge_packet" => {
                let ctx = sample_edge();
                let payload = b"semantic open payload";
                let sid = session_seed(function_name, iteration) * 2;
                let mut frame = [0u8; 96];
                let mut frame_len = 0usize;
                let mut out = [0u8; 96];
                let mut out_len = 0usize;
                seal_edge_packet(
                    payload.as_ptr(),
                    payload.len(),
                    &ctx,
                    sid,
                    frame.as_mut_ptr(),
                    frame.len(),
                    &mut frame_len,
                ) == 0
                    && open_edge_packet(
                        frame.as_ptr(),
                        frame_len,
                        &ctx,
                        sid + 1,
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    ) == 0
                    && &out[..out_len] == payload
            }
            "choreograph_packet" => {
                let in_ctx = EdgeContext {
                    intent_id: 1,
                    edge_id: 1,
                    sequence: iteration,
                };
                let out_ctx = EdgeContext {
                    intent_id: 1,
                    edge_id: 2,
                    sequence: iteration + 1,
                };
                let payload = [7u8; 32];
                let sid = session_seed(function_name, iteration) * 3;
                let mut frame = [0u8; 96];
                let mut frame_len = 0usize;
                let mut out = [0u8; 96];
                let mut out_len = 0usize;
                seal_edge_packet(
                    payload.as_ptr(),
                    payload.len(),
                    &in_ctx,
                    sid,
                    frame.as_mut_ptr(),
                    frame.len(),
                    &mut frame_len,
                ) == 0
                    && choreograph_packet(
                        frame.as_mut_ptr(),
                        frame_len,
                        &in_ctx,
                        &out_ctx,
                        sid + 1,
                    ) == 0
                    && open_edge_packet(
                        frame.as_ptr(),
                        frame_len,
                        &out_ctx,
                        sid + 2,
                        out.as_mut_ptr(),
                        out.len(),
                        &mut out_len,
                    ) == 0
                    && &out[..out_len] == payload
            }
            "noise_sign_payload" => {
                let mut sig = [0u8; 64];
                noise_sign_payload(
                    b"payload".as_ptr(),
                    7,
                    sig.as_mut_ptr(),
                    session_seed(function_name, iteration),
                ) == 0
                    && sig.iter().any(|byte| *byte != 0)
            }
            _ => false,
        }
    }

    fn run_modular_behavior_case(function_name: &str, kind: &str) {
        let _guard = MODULAR_TEST_LOCK.lock().unwrap();
        init_enclave_keys();
        let iterations = match kind {
            "load" => 16,
            "stress" => 64,
            "chaos" => 8,
            "security" => 8,
            "benchmark" => 128,
            _ => 4,
        };
        let rss_start = rss_bytes();
        let cpu_start = cpu_seconds();
        let started = Instant::now();
        let mut max_rss = rss_start;
        let mut passed = true;
        for iteration in 0..iterations {
            passed &= exercise_function(function_name, iteration);
            max_rss = max_rss.max(rss_bytes());
        }
        let wall_ns = started.elapsed().as_nanos();
        let cpu_delta = (cpu_seconds() - cpu_start).max(0.0);
        let rss_end = rss_bytes();
        write_modular_report(
            function_name,
            kind,
            iterations,
            wall_ns,
            cpu_delta,
            rss_start,
            rss_end,
            max_rss,
            passed,
        );
        assert!(passed, "{kind} behavior failed for {function_name}");
    }
}
