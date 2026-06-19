// MIASMA-WORM defense: scope-bound signing and verification.
//
// `noise_sign_payload` signs raw bytes with no context. A MIASMA worm that
// obtains a signing key (via process-memory access, supply-chain poisoning, or
// RCE against a downstream agent) can then sign ANY payload for ANY recipient,
// forwarding instructions that appear legitimate to the rest of the agent mesh.
//
// These two functions prevent that by including a non-forgeable scope in every
// signature:
//
//   signing_input = SCOPED_SIG_DOMAIN       (22 bytes — cross-protocol separation)
//                   || signer_pubkey        (32 bytes — who signs, non-repudiable)
//                   || scope.recipient_pubkey (32 bytes — signature is ONLY valid for this agent)
//                   || scope.operation       (16 bytes — what operation is authorized)
//                   || session_id_le8        ( 8 bytes — prevents cross-session replay)
//                   || payload_hash          (32 bytes — SHA-256 of the actual payload)
//
// A worm that captures key K and tries to relay K's signatures to a different
// agent will fail at `noise_verify_scoped_signature`: the recipient_pubkey in
// the scope doesn't match the receiving agent's key.
//
// A worm that tries to use a "seal_snapshot" key for "route_packet" will fail
// because the operation field differs.

const SCOPED_SIG_DOMAIN: &[u8; 22] = b"LSES-SCOPED-SIG-V1\0\0\0\0";

/// Context supplied by the caller to bind the signature to a specific recipient
/// and operation. Both fields are fixed-width to prevent length-extension attacks.
#[repr(C)]
pub struct ScopedSignatureContext {
    /// Ed25519 public key (32 bytes) of the INTENDED recipient.
    /// A signature produced with recipient=B cannot be accepted by agent C.
    pub recipient_pubkey: [u8; 32],
    /// ASCII operation name, zero-padded to 16 bytes (e.g. b"seal_snapshot\0\0\0").
    /// A signature issued for operation X cannot authorize operation Y.
    pub operation: [u8; 16],
}

/// Sign `payload` with a scope that binds the signature to a specific recipient
/// and operation. Uses the enclave's current signing key.
///
/// Returns 0 on success; on success the 64-byte Ed25519 signature is written to
/// `out_sig`. The session replay bitmap is consumed to prevent replay.
#[no_mangle]
pub extern "C" fn noise_sign_scoped_payload(
    payload_ptr: *const u8,
    len: usize,
    scope: *const ScopedSignatureContext,
    session_id: u64,
    out_sig: *mut u8,
) -> i32 {
    if payload_ptr.is_null() || scope.is_null() || out_sig.is_null() {
        return ERR_NULL_POINTER;
    }

    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    if !guard.try_mark_replay(session_id) {
        return ERR_REPLAY;
    }

    let sk = match &guard.signing_key {
        Some(k) => k,
        None => return ERR_STATE,
    };

    let scope_ref = unsafe { &*scope };
    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, len) };

    let payload_hash = Sha256::digest(payload);
    let signer_pubkey = sk.verifying_key().to_bytes();
    let session_bytes = session_id.to_le_bytes();

    let mut signing_input = Vec::with_capacity(22 + 32 + 32 + 16 + 8 + 32);
    signing_input.extend_from_slice(SCOPED_SIG_DOMAIN);
    signing_input.extend_from_slice(&signer_pubkey);
    signing_input.extend_from_slice(&scope_ref.recipient_pubkey);
    signing_input.extend_from_slice(&scope_ref.operation);
    signing_input.extend_from_slice(&session_bytes);
    signing_input.extend_from_slice(payload_hash.as_slice());

    let signature = sk.sign(&signing_input);
    unsafe { core::ptr::copy_nonoverlapping(signature.to_bytes().as_ptr(), out_sig, 64) };
    0
}

/// Verify a scoped signature produced by `noise_sign_scoped_payload`.
///
/// In addition to signature correctness this function verifies that:
/// - The signature was intended FOR THIS enclave (recipient_pubkey matches our
///   current signing key), blocking MIASMA forwarding to wrong agents.
/// - The operation field matches what the verifier expects.
///
/// Returns 0 on success, ERR_AUTHENTICATION if any check fails.
#[no_mangle]
pub extern "C" fn noise_verify_scoped_signature(
    payload_ptr: *const u8,
    len: usize,
    scope: *const ScopedSignatureContext,
    session_id: u64,
    signer_pubkey: *const u8, // 32-byte claimed signer's public key
    sig: *const u8,           // 64-byte Ed25519 signature
) -> i32 {
    use subtle::ConstantTimeEq;

    if payload_ptr.is_null() || scope.is_null() || signer_pubkey.is_null() || sig.is_null() {
        return ERR_NULL_POINTER;
    }

    let guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    // Verify that the recipient_pubkey in the scope matches OUR current key.
    // A MIASMA worm that captures a signature for agent B and relays it to agent C
    // will fail here: the recipient_pubkey was B's key, not C's.
    let our_pubkey = match &guard.signing_key {
        Some(sk) => sk.verifying_key().to_bytes(),
        None => return ERR_STATE,
    };
    let scope_ref = unsafe { &*scope };
    let intended_for_us: bool = scope_ref.recipient_pubkey.ct_eq(&our_pubkey).into();
    if !intended_for_us {
        return ERR_AUTHENTICATION;
    }

    let pk_bytes: [u8; 32] = unsafe { core::ptr::read(signer_pubkey as *const [u8; 32]) };
    let sig_bytes: [u8; 64] = unsafe { core::ptr::read(sig as *const [u8; 64]) };

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return ERR_CRYPTO,
    };

    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, len) };
    let payload_hash = Sha256::digest(payload);
    let session_bytes = session_id.to_le_bytes();

    let mut signing_input = Vec::with_capacity(22 + 32 + 32 + 16 + 8 + 32);
    signing_input.extend_from_slice(SCOPED_SIG_DOMAIN);
    signing_input.extend_from_slice(&pk_bytes);
    signing_input.extend_from_slice(&scope_ref.recipient_pubkey);
    signing_input.extend_from_slice(&scope_ref.operation);
    signing_input.extend_from_slice(&session_bytes);
    signing_input.extend_from_slice(payload_hash.as_slice());

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    match verifying_key.verify_strict(&signing_input, &signature) {
        Ok(_) => 0,
        Err(_) => ERR_AUTHENTICATION,
    }
}
