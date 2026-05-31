fn derive_edge_key(ctx: &EdgeContext, root_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(root_seed).expect("HMAC accepts any key size");
    mac.update(&ctx.intent_id.to_le_bytes());
    mac.update(&ctx.edge_id.to_le_bytes());
    mac.update(&ctx.sequence.to_le_bytes());
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes()[..32]);
    key
}
