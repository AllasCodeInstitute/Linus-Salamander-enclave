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
    let key = zeroize::Zeroizing::new(derive_edge_key(edge, &*root_seed));
    let cipher = match Aes256Gcm::new_from_slice(&*key) {
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
            Err(_) => {
                ciphertext.zeroize();
                return ERR_CRYPTO;
            }
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
    ciphertext.zeroize();

    0
}
