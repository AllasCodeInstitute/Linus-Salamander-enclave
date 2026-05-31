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
