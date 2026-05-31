fn mark_replay_and_get_root_seed(session_id: u64) -> Result<[u8; 32], i32> {
    let mut guard = state().lock().map_err(|_| ERR_STATE)?;
    if !guard.try_mark_replay(session_id) {
        return Err(ERR_REPLAY);
    }
    Ok(guard.root_seed)
}
