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
