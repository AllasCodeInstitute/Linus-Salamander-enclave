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
