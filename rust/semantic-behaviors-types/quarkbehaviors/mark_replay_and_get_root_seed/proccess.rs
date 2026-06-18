fn mark_replay_and_get_root_seed(session_id: u64) -> Result<zeroize::Zeroizing<[u8; 32]>, i32> {
    let mut guard = state().lock().map_err(|_| ERR_STATE)?;
    if !guard.try_mark_replay(session_id) {
        return Err(ERR_REPLAY);
    }
    // CVE-LSES-019: Wrap in Zeroizing so the stack copy is cleared on drop.
    Ok(zeroize::Zeroizing::new(guard.root_seed))
}
