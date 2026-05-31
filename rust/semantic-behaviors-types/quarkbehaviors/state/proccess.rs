fn state() -> &'static Mutex<EnclaveState> {
    STATE.get_or_init(|| Mutex::new(EnclaveState::new()))
}
