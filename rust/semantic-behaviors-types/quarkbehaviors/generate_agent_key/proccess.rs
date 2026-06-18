const AGENT_KEY_MAX_FIELD_LEN: usize = 1024;

fn encode_field_len_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    let len = (field.len() as u32).to_be_bytes();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(field);
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
    // CVE-LSES-013: Enforce upper bounds to prevent buffer overread in from_raw_parts.
    if name_len > AGENT_KEY_MAX_FIELD_LEN
        || caps_len > AGENT_KEY_MAX_FIELD_LEN
        || plane_len > AGENT_KEY_MAX_FIELD_LEN
        || semantics_len > AGENT_KEY_MAX_FIELD_LEN
    {
        return ERR_NULL_POINTER;
    }

    let guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return ERR_STATE,
    };

    // CVE-LSES-010: Use HKDF-SHA256 with domain separation and length-prefixed fields.
    // HKDF treats root_seed as IKM and the labeled, length-prefixed field block as info,
    // preventing field-concatenation collisions and using the seed as a proper PRF key.
    use hkdf::Hkdf;

    let name_bytes = unsafe { core::slice::from_raw_parts(name, name_len) };
    let caps_bytes = unsafe { core::slice::from_raw_parts(caps, caps_len) };
    let plane_bytes = unsafe { core::slice::from_raw_parts(plane, plane_len) };
    let semantics_bytes = unsafe { core::slice::from_raw_parts(semantics, semantics_len) };

    let mut info = Vec::with_capacity(
        18 + 4 + name_len + 4 + caps_len + 4 + plane_len + 4 + semantics_len,
    );
    info.extend_from_slice(b"LSES-AGENT-KEY-V1\x00");
    encode_field_len_prefixed(&mut info, name_bytes);
    encode_field_len_prefixed(&mut info, caps_bytes);
    encode_field_len_prefixed(&mut info, plane_bytes);
    encode_field_len_prefixed(&mut info, semantics_bytes);

    let hk = Hkdf::<sha2::Sha256>::new(None, &guard.root_seed);
    let mut okm = [0u8; 32];
    if hk.expand(&info, &mut okm).is_err() {
        return ERR_CRYPTO;
    }

    unsafe { core::ptr::copy_nonoverlapping(okm.as_ptr(), out_key, 32) };
    okm.zeroize();
    info.as_mut_slice().zeroize();
    0
}
