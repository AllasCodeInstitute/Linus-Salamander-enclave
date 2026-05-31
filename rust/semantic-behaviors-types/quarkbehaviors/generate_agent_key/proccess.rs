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
