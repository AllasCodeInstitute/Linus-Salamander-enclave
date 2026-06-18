// CVE-LSES-006: Choreography is an AEAD re-encryption step, not a keyed XOR.
// The input buffer must be a complete AEAD frame for `in_ctx`:
//   nonce || ciphertext || tag
// On success the same buffer is overwritten with a fresh AEAD frame for `out_ctx`.
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
    if len < AEAD_OVERHEAD {
        return ERR_AUTHENTICATION;
    }

    let in_edge = unsafe { &*in_ctx };
    let out_edge = unsafe { &*out_ctx };

    if in_edge.intent_id == out_edge.intent_id
        && in_edge.edge_id == out_edge.edge_id
        && in_edge.sequence == out_edge.sequence
    {
        return ERR_CRYPTO;
    }

    let root_seed = match mark_replay_and_get_root_seed(session_id) {
        Ok(seed) => seed,
        Err(code) => return code,
    };

    let plaintext_len = len - AEAD_OVERHEAD;
    let frame = unsafe { core::slice::from_raw_parts_mut(payload_ptr, len) };
    let nonce_in = Nonce::from_slice(&frame[..AEAD_NONCE_LEN]);
    let tag_in = aes_gcm::Tag::from_slice(&frame[AEAD_NONCE_LEN + plaintext_len..]);
    let aad_in = edge_context_aad(in_edge);
    let mut plaintext = frame[AEAD_NONCE_LEN..AEAD_NONCE_LEN + plaintext_len].to_vec();

    let key_in = zeroize::Zeroizing::new(derive_edge_key(in_edge, &*root_seed));
    let cipher_in = match Aes256Gcm::new_from_slice(&*key_in) {
        Ok(cipher) => cipher,
        Err(_) => return ERR_CRYPTO,
    };
    if cipher_in
        .decrypt_in_place_detached(nonce_in, &aad_in, &mut plaintext, tag_in)
        .is_err()
    {
        plaintext.zeroize();
        return ERR_AUTHENTICATION;
    }

    let key_out = zeroize::Zeroizing::new(derive_edge_key(out_edge, &*root_seed));
    let cipher_out = match Aes256Gcm::new_from_slice(&*key_out) {
        Ok(cipher) => cipher,
        Err(_) => return ERR_CRYPTO,
    };
    let mut nonce_out = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_out);
    let aad_out = edge_context_aad(out_edge);
    let tag_out = match cipher_out.encrypt_in_place_detached(
        Nonce::from_slice(&nonce_out),
        &aad_out,
        &mut plaintext,
    ) {
        Ok(tag) => tag,
        Err(_) => {
            plaintext.zeroize();
            return ERR_CRYPTO;
        }
    };

    frame[..AEAD_NONCE_LEN].copy_from_slice(&nonce_out);
    frame[AEAD_NONCE_LEN..AEAD_NONCE_LEN + plaintext_len].copy_from_slice(&plaintext);
    frame[AEAD_NONCE_LEN + plaintext_len..].copy_from_slice(tag_out.as_slice());
    plaintext.zeroize();
    nonce_out.zeroize();

    0
}
